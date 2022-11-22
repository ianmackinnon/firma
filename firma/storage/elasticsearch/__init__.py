import re
import sys
import json
import logging
import argparse
import warnings
from getpass import getpass
from io import IOBase
from difflib import ndiff
from typing import Union, Iterable
from pathlib import Path
from urllib.parse import urlparse, urlunparse

import urllib3
import humanize
import requests
from requests.auth import HTTPBasicAuth

from firma.util.env import load_env_multi



DEFAULT_API_ROOT = "http://localhost:9200"
CHUNK_SIZE_DOCS = 2**8
MIME_JSON = "application/json"
MIME_NEWLINE_DELIMITED_JSON = "application/x-ndjson"
COMMAND_LIST = {
    "put-roles",
    "delete-roles",
    "compare-roles",
    "put-users",
    "delete-users",
    "compare-users",
    "put-indices",
    "delete-indices",
    "compare-indices",
    "index-docs",
    "delete-docs",
}
USERS = [
    "ADMIN",
]



JsonObject = Union[dict, list, str, float, int, bool, None]

class EsException(Exception):
    def __init__(self, *args, **kwargs):
        self.data = None
        self.type = None

        response = kwargs.pop("response", None)
        if response is not None:
            self.data = response.json()
            self.type = self.data["error"]["type"]

        super().__init__(*args, **kwargs)



LOG = logging.getLogger('elasticsearch')



def query_error(response):
    return json.dumps(response.json(), sort_keys=True, indent=2)



def user_name(account):
    return f"ES_USER_{account}_NAME"



def user_pass(account):
    return f"ES_USER_{account}_PASS"



def user_role(account):
    return f"ES_USER_{account}_ROLE"



def env_accounts(env):
    name_set = dict()
    pass_set = dict()
    role_set = dict()

    for k in env:
        if match := re.match(r"ES_USER_(ADMIN)_(NAME|PASS|ROLE)$", k):
            account, item = match.groups()
            if item == "NAME":
                name_set[account] = True
            elif item == "PASS":
                pass_set[account] = True
            else:
                role_set[account] = True

    if not (name_set == pass_set == role_set):
        LOG.error(".env ES user variables do not fully match:")
        LOG.error("ES_USER_..._NAME:  %s", ", ".join(name_set))
        LOG.error("ES_USER_..._PASS:  %s", ", ".join(pass_set))
        LOG.error("ES_USER_..._ROLE:  %s", ", ".join(role_set))
        sys.exit(1)

    if not name_set:
        LOG.error("No .env ES user variables are defined.")
        sys.exit(1)

    return list(name_set)



def load_env(env_path: Path):
    return load_env_multi([
        env_path / ".env",
        env_path / ".env.local",
    ])



def get_search(
        env: dict,
        account: str,
):
    assert account in ["elastic"] + USERS

    auth = None

    if account == "elastic":
        auth = account
    else:
        auth = {
            "username": env[user_name(account)],
            "password": env[user_pass(account)],
        }

    return Es(
        api_root=env["ES_API_ROOT"],
        prefix=env["ES_PREFIX"],
        ssl_cert=env.get("ES_SSL_CERT", None) or False,
        auth=auth,
    )



# Es Functions



class Es():
    """
    Controller for Elasticsearch indices.

    A default index name may be supplied.
    """

    def __init__(
            self,
            api_root: str | None = None,
            prefix: str | None = None,
            ssl_cert: Path | bool | None = None,
            auth: str | None = None,
            request_log: logging.Logger | None = None,
            request_log_format: str | None = None,
    ):

        self.api_root = api_root
        self.prefix = prefix
        self.ssl_cert = ssl_cert
        if self.ssl_cert is False:
            warnings.filterwarnings(
                action='ignore',
                category=urllib3.connectionpool.InsecureRequestWarning,
                module='urllib3.connectionpool'
            )
        self.auth = auth

        self.request_log = request_log
        self.request_log_format = request_log_format
        if self.request_log_format is None:
            self.request_log_format = "console_req"

        self._basic_auth_creds = {}
        self._bulk_buffer = []


    @property
    def request_kwargs(self):
        kwargs = {}

        if self.auth:
            if isinstance(self.auth, dict):
                kwargs["auth"] = HTTPBasicAuth(
                    self.user_name(self.auth["username"]),
                    self.auth["password"]
                )
            else:
                kwargs["auth"] = self.auth_password(self.auth)

        if self.ssl_cert is not None:
            kwargs["verify"] = self.ssl_cert

        return kwargs


    def log_request(self, method, url, data=None, nd=None):
        if not self.request_log:
            return

        if self.request_log_format in ("console", "console_req"):
            path = url[len(self.api_root):]
            msg = f" REQUEST\n{method.upper()} {path}"
            if data:
                if nd:
                    for item in data.split("\n"):
                        msg += f"\n{json.dumps(item, indent=2)}"
                else:
                    msg += f"\n{json.dumps(data, indent=2)}"
        elif self.request_log_format in ("curl", "cur_req"):
            ct = MIME_NEWLINE_DELIMITED_JSON if nd else MIME_JSON
            msg = f" REQUEST\ncurl -v -X {method.upper()} -H Content-Type='{ct}; charset=UTF-8' {url}"
            if data:
                msg += "-d '"
                if nd:
                    msg += data
                else:
                    msg += json.dumps(data, indent=2)
                msg += "'"

        self.request_log.info(msg)


    def log_response(self, response):
        if not self.request_log:
            return

        if "req" in self.request_log_format:
            return

        msg = f" RESPONSE {response.status_code}"
        data = response.json()
        if data:
            msg += f"\n{json.dumps(data, indent=2)}"

        self.request_log.info(msg)


    def auth_password(
            self,
            username: str
    ):
        if username not in self._basic_auth_creds:
            self._basic_auth_creds[username] = getpass(
                prompt=f"Password for Elasticsearch user `{username}`: ")
        return HTTPBasicAuth(username, self._basic_auth_creds[username])


    def put_role(
            self,
            name: str,
            definition: Union[str, Path, IOBase, dict],
    ):
        LOG.debug(f"Loading role definition: `{definition}`.")
        definition = self._load_definition_object(definition, replace_prefix=True)

        if self.prefix:
            name = f"{self.prefix}-{name}"

        url = f"{self.api_root}/_security/role/{name}"

        LOG.debug(f"Putting role definition: {name}.")
        self.log_request("put", url)
        response = requests.put(url, json=definition, **self.request_kwargs)
        self.log_response(response)
        if response.status_code != 200:
            LOG.error(query_error(response))
            raise EsException("Failed to put ES role.")
        LOG.debug("OK")


    def delete_role(
            self,
            name: str,
    ):
        if self.prefix:
            name = f"{self.prefix}-{name}"

        url = f"{self.api_root}/_security/role/{name}"

        LOG.debug(f"Deleting role definition: {name}.")
        self.log_request("delete", url)
        response = requests.delete(url, **self.request_kwargs)
        self.log_response(response)
        if response.status_code != 200:
            LOG.error(query_error(response))
            raise EsException("Failed to delete ES role.")
        LOG.debug("OK")


    def user_name(self, name):
        if self.prefix:
            name = f"{self.prefix}-{name}"
        return name


    def put_user(
            self,
            name: str,
            definition: Union[str, Path, IOBase, dict],
    ):
        message = definition
        if isinstance(message, dict):
            message = ", ".join(message["roles"])

        LOG.debug(f"Loading user definition: `{message}`.")
        definition = self._load_definition_object(definition, replace_prefix=True)

        name = self.user_name(name)

        url = f"{self.api_root}/_security/user/{name}"

        LOG.debug(f"Putting user definition: {name}.")
        self.log_request("put", url)
        response = requests.put(url, json=definition, **self.request_kwargs)
        self.log_response(response)
        if response.status_code != 200:
            LOG.error(query_error(response))
            raise EsException("Failed to put ES user.")
        LOG.debug("OK")


    def delete_user(
            self,
            name: str,
    ):
        LOG.debug(f"Deleting user definition: `{name}`.")
        name = self.user_name(name)

        url = f"{self.api_root}/_security/user/{name}"

        LOG.debug(f"Deleting user definition: {name}.")
        self.log_request("delete", url)
        response = requests.delete(url, **self.request_kwargs)
        self.log_response(response)
        if response.status_code != 200:
            LOG.error(query_error(response))
            raise EsException("Failed to delete ES user.")
        LOG.debug("OK")


    def _calc_index_name(
            self,
            index_name: [str, None],
    ) -> Union[str, None]:
        """
        Calculate the index name for member functions.
        It may still be none

        Index name may be a comma separated string.
        """

        if index_name and self.prefix:
            index_name = ",".join([
                v if v.startswith(self.prefix + "-")
                else self.prefix + "-" + v
                for v in index_name.split(",")
            ])

        return index_name


    def _calc_url(
            self,
            index_name: str,
    ) -> str:
        index_name = self._calc_index_name(index_name)

        url = self.api_root
        if index_name is not None:
            url += "/" + index_name

        return url


    def _load_definition_object(
            self,
            definition: Union[str, Path, IOBase, dict],
            replace_prefix: bool | None = None
    ):
        if isinstance(definition, str):
            definition = Path(definition)
        if isinstance(definition, Path):
            text = definition.read_text(encoding="utf-8")
            if self.prefix and replace_prefix:
                text = text.replace("{PREFIX}", f"{self.prefix}-")
            definition = json.loads(text)
        if isinstance(definition, IOBase):
            raise NotImplementedError()
            definition = json.load(definition)

        assert isinstance(definition, dict)

        return definition


    def refresh(
            self,
            index_name: str,
    ) -> None:

        index_name = self._calc_index_name(index_name)
        url = self._calc_url(index_name) + "/_refresh"

        self.log_request("post", url)
        response = requests.post(url, **self.request_kwargs)
        self.log_response(response)
        if response.status_code != 200:
            LOG.error(query_error(response))
            raise EsException("Failed to refresh ES node.")
        LOG.debug("OK")


    def count(
            self,
            index_name: str,
    ) -> int:
        url = self._calc_url(index_name) + "/_count"

        self.log_request("post", url)
        response = requests.post(url, **self.request_kwargs)
        self.log_response(response)
        if response.status_code != 200:
            raise EsException("Failed to count documents.", response=response)

        result = response.json()

        return result["count"]


    def search(
            self,
            index_name: str,
            query,
    ):

        index_name = self._calc_index_name(index_name)
        url = self._calc_url(index_name) + "/_search"

        self.log_request("post", url, query)
        response = requests.post(url, json=query, **self.request_kwargs)
        self.log_response(response)
        if response.status_code != 200:
            LOG.error(query_error(response))
            raise EsException("Failed to search.")

        result = response.json()

        return result


    def document(self, document_id, index=None):
        raise NotImplementedError()

        if index is None:
            index = self.index_name

        url = self.api_root
        if index is not None:
            url += "/" + index
        url += f"/{document_id}"

        self.log_request("get", url)
        response = requests.get(url, **self.request_kwargs)
        self.log_response(response)
        if response.status_code != 200:
            LOG.error(query_error(response))
            raise EsException("Failed to search.")

        result = response.json()

        result.update({
            "id": document_id
        })

        return result


    def put_index(
            self,
            name: str,
            definition: Union[str, Path, IOBase, dict],
    ):
        name = self._calc_index_name(name)
        definition = self._load_definition_object(definition)

        url = self._calc_url(name)

        # Unlike user and role, PUT index will fail if it exists:
        self.delete_index(name)

        # Create a new index with our index definition
        LOG.info("Creating ES index '%s'.", name)
        self.log_request("put", url, definition)
        response = requests.put(url, json=definition, **self.request_kwargs)
        self.log_response(response)
        if response.status_code != 200:
            LOG.error(query_error(response))
            raise EsException(
                "Failed to create ES index `{name}`.",
                response=response)
        LOG.info("Created ES index `%s`.", name)


    def delete_index(
            self,
            name: str,
    ) -> None:
        """
        Attempt to delete index.
        """
        name = self._calc_index_name(name)
        url = self._calc_url(name)

        # If a index with the same name alread exists, delete it.
        LOG.info("Deleting ES index `%s`.", name)
        self.log_request("delete", url)
        response = requests.delete(url, **self.request_kwargs)
        self.log_response(response)
        if response.status_code == 404:
            LOG.debug("ES index `%s` did not exist.", name)
        elif response.status_code != 200:
            LOG.error(query_error(response))
            raise EsException(
                "Failed to delete ES index `{name}`.",
                response=response)
        else:
            LOG.info("Deleted ES index `%s`.", name)


    def index(
            self,
            index_name: str,
            document,
            id_=None
    ):
        index_name = self._calc_index_name(index_name)
        url = self._calc_url(index_name) + "/_doc"

        if id_ is None:
            method = "post"
        else:
            method = "put"
            url += f"/{str(id_)}"

        # Create a new index with our index definition
        LOG.info("Indexing document.")
        self.log_request(method, url, document)
        response = requests.request(method, url, json=document, **self.request_kwargs)
        self.log_response(response)
        if not str(response.status_code).startswith("2"):
            LOG.error(query_error(response))
            raise EsException(f"Failed to index document `{response.status_code}`.")


    def delete(
            self,
            index_name: str,
            id_=None
    ) -> None:
        index_name = self._calc_index_name(index_name)
        url = self._calc_url(index_name) + f"/_doc/{str(id_)}"

        # Create a new index with our index definition
        LOG.info("deleting document.")
        self.log_request("delete", url)
        response = requests.delete(url, **self.request_kwargs)
        self.log_response(response)
        if not str(response.status_code).startswith("2"):
            LOG.error(query_error(response))
            raise EsException(f"Failed to delete document `{response.status_code}`.")


    def delete_all(
            self,
            index_name: str,
    ) -> None:
        index_name = self._calc_index_name(index_name)
        url = self._calc_url(index_name) + "/_delete_by_query"

        query = {
            "query": {
                "match_all": {},
            }
        }

        # Create a new index with our index definition
        LOG.info("deleting all documents in {index_name}.")
        self.log_request("delete", url)
        response = requests.post(url, json=query, **self.request_kwargs)
        self.log_response(response)
        if not str(response.status_code).startswith("2"):
            LOG.error(query_error(response))
            raise EsException(f"Failed to delete document `{response.status_code}`.")


    def mapping(
            self,
            index_name: str,
    ) -> JsonObject:
        index_name = self._calc_index_name(index_name)
        url = self._calc_url(index_name) + "/_mapping"

        self.log_request("get", url)
        response = requests.get(url, **self.request_kwargs)
        self.log_response(response)
        if response.status_code != 200:
            raise EsException("Failed to retrieve mapping.", response=response)

        result = response.json()

        if index_name:
            return result[index_name]

        return result


    def index_queue(
            self,
            index_name: str,
            document,
            id_=None,
            auto=True,
    ) -> None:
        action_data = {
            "index": {},
        }
        if index_name is not None:
            index_name = self._calc_index_name(index_name)
            if index_name:
                action_data["index"]["_index"] = index_name

        if id_ is not None:
            action_data["index"]["_id"] = id_

        self._bulk_buffer += [action_data, document]

        if auto and len(self._bulk_buffer) >= CHUNK_SIZE_DOCS:
            self.bulk(index_name)


    def delete_queue(
            self,
            index_name: str,
            id_=None,
            auto=True,
    ) -> None:
        action_data = {
            "delete": {},
        }
        if index_name is not None:
            index_name = self._calc_index_name(index_name)
            if index_name:
                action_data["delete"]["_index"] = index_name

        if id_ is not None:
            action_data["delete"]["_id"] = id_

        self._bulk_buffer += [action_data]

        if auto and len(self._bulk_buffer) >= CHUNK_SIZE_DOCS:
            self.bulk(index_name)


    def bulk(
            self,
            index_name: str,
    ) -> JsonObject:

        if not self._bulk_buffer:
            return None

        index_name = self._calc_index_name(index_name)
        url = self._calc_url(index_name) + "/_bulk"

        payload = "".join([json.dumps(v) + "\n" for v in self._bulk_buffer])
        payload_length_doc = len(self._bulk_buffer) / 2
        payload_length_mem = len(payload)
        self._bulk_buffer = []

        LOG.debug(
            "ES bulk insert of %d records, ~%s bytes",
            payload_length_doc, humanize.naturalsize(payload_length_mem, binary=True))
        self.log_request("post", url, payload, nd=True)
        response = requests.post(url, data=payload, headers={
            "content-type": MIME_NEWLINE_DELIMITED_JSON,
        }, **self.request_kwargs)
        self.log_response(response)
        if response.status_code != 200:
            LOG.error(query_error(response))
            raise EsException("Bulk action failed.")
        result = response.json()
        if result["errors"]:
            for item in result["items"]:
                key = next(iter(item))
                status = item[key]["status"]
                if status >= 400:
                    LOG.error(item)
            raise EsException("Some bulk actions failed.")

        return result



# Management functions



def put_indices(
        es: Es,
        indices: dict,
):
    """
    `indices` is a dict of `{name: definition}`.
    """

    for name, definition in indices.items():
        es.put_index(name, definition)



def delete_indices(
        es: Es,
        indices: dict,
):
    LOG.info("delete-indices")
    for name in indices:
        es.delete_index(name)



def compare_indices(
        es: Es,
        indices: dict,
) -> bool:
    """
    Return whether mappings differ.
    """

    fail = False

    for name, definition in indices.items():
        definition_obj = es._load_definition_object(definition)
        mapping = es.mapping(index_name=name)

        if definition_obj != mapping:
            LOG.warning(name)
            LOG.warning(definition)
            diff = ndiff(
                json.dumps(definition_obj, indent=2).splitlines(),
                json.dumps(mapping, indent=2).splitlines(),
            )
            LOG.warning("".join(diff))
            fail = True

    return fail



def delete_docs(
        es: Es,
        indices: dict,
):
    LOG.info("delete-docs")
    for name in indices:
        es.delete(name)



# Management parser and main



def verify_uri(text: str) -> str:
    return urlunparse(urlparse(text))



def put_roles(
        es: Es,
        roles: dict,
):
    for name, path in roles.items():
        es.put_role(name, path)



def put_users(
        es: Es,
        env: dict,
        users: Iterable,
):
    for account in users:
        definition = {
            "password" : env[user_pass(account)],
        }
        role = env[user_role(account)]
        prefix = env.get("ES_PREFIX", None)
        if prefix:
            role = f"{prefix}-{role}"
        definition["roles"] = [
            role,
        ]

        es.put_user(env[user_name(account)], definition)



def delete_users(
        es: Es,
        env: dict,
        users: Iterable,
):
    for account in users:
        es.delete_user(env[user_name(account)])



def get_users(
        es: Es,
):
    url = f"{es.api_root}/_security/user/"

    response = requests.get(url, **es.request_kwargs)
    if response.status_code != 200:
        LOG.error(query_error(response))
        raise EsException("Failed to get ES users.")

    data = response.json()

    for user in data:
        if not user.startswith(es.prefix):
            continue

        print(f"user: {user}")
        for k, v in data[user].items():
            if not v:
                continue
            if k == "roles":
                v = ", ".join(v)
            print(f"  {k:16}: {v}")
        print()



def delete_roles(
        es: Es,
        roles: dict,
):
    for name in roles:
        es.delete_role(name)



def get_roles(
        es: Es,
):
    url = f"{es.api_root}/_security/role/"

    response = requests.get(url, **es.request_kwargs)
    if response.status_code != 200:
        LOG.error(query_error(response))
        raise EsException("Failed to get ES roless.")

    data = response.json()

    for role in data:
        if not role.startswith(es.prefix):
            continue


        print(f"role: {role}")
        for index in data[role]["indices"]:
            names = index.pop("names")
            print(f"  index: {', '.join(names)}")
            for k, v in index.items():
                if not v:
                    continue

                if isinstance(v, list):
                    v = ", ".join(v)

                print(f"    {k:14}: {v}")
            print()



def create_manage_parser(desc: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=desc)

    parser.add_argument(
        "--verbose", "-v",
        action="count", default=0,
        help="Print verbose information for debugging.")
    parser.add_argument(
        "--quiet", "-q",
        action="count", default=0,
        help="Suppress warnings.")

    parser.add_argument(
        "--index-name", "-i",
        action="append",
        help="Only work on the supplied indices.")

    parser.add_argument(
        "--env", "-E",
        action="store", dest="env_path",
        type=Path,
        help="Path to directory of .env files.")

    parser.add_argument(
        "command",
        metavar="COMMAND",
        nargs="+",
        help=f"One or more of {', '.join([f'`{v}`' for v in COMMAND_LIST])}.")

    return parser



def filter_indices(
        args: argparse.Namespace,
        indices: dict,
) -> dict:
    if args.index_name:
        return {k: v for k, v in indices.items() if k in args.index_name}
    return indices



def manage_main(
        args: argparse.Namespace,
        env: dict,
        roles: dict,
        indices: dict,
) -> None:
    es = get_search(env, account="elastic")

    if "delete-indices" in args.command:
        delete_indices(es, indices)

    if "delete-users" in args.command:
        delete_users(es, env, USERS)

    if "delete-roles" in args.command:
        delete_roles(es, roles)

    if "put-roles" in args.command:
        put_roles(es, roles)

    if "put-users" in args.command:
        put_users(es, env, USERS)

    if "put-indices" in args.command:
        put_indices(es, indices)

    if "get-users" in args.command:
        get_users(es)

    if "get-roles" in args.command:
        get_roles(es)
