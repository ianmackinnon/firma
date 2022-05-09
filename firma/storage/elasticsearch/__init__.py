import sys
import enum
import json
import logging
import argparse
import warnings
from getpass import getpass
from io import IOBase
from difflib import ndiff
from typing import Union, Callable
from pathlib import Path
from urllib.parse import urlparse, urlunparse

import urllib3
import humanize
import requests
from requests.auth import HTTPBasicAuth

from firma.util import load_conf



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



def get_conf(
        path: Path,
        **kwargs
) -> dict:
    config = load_conf(path)
    if "elasticsearch" not in config:
        raise Exception(
            f"Section `elasticsearch` is required but not present in configuration file {str(path)}.")

    api_root = config.get("elasticsearch", "api-root", fallback=DEFAULT_API_ROOT)
    api_root = verify_uri(api_root)

    data = {
        "api_root": api_root,
    }

    if "prefix" in config["elasticsearch"]:
        data["prefix"] = config["elasticsearch"]["prefix"]

    if "ssl_cert" in config["elasticsearch"]:
        data["ssl_cert"] = config["elasticsearch"]["ssl_cert"]
        if data["ssl_cert"].lower() == "false":
            data["ssl_cert"] = False

    if admin_conf := config.get("elasticsearch-admin", "username", fallback=None):
        data["user_admin"] = {
            "username": config.get("elasticsearch-admin", "username", fallback=None),
            "password": config.get("elasticsearch-admin", "password", fallback=None),
            "role": config.get("elasticsearch-admin", "role", fallback=None),
        }

    if kwargs:
        if api_root := kwargs.get("api_root", None):
            data["api_root"] = api_root
        if api_prefix := kwargs.get("prefix", None):
            data["prefis"] = prefix

    assert data["prefix"]

    return data



def get_search_factory(conf_path, user_key):
    def get_search(**kwargs):
        config = get_conf(conf_path, kwargs=kwargs)

        es = Es(
            api_root=config["api_root"],
            prefix=config["prefix"],
            ssl_cert=config["ssl_cert"],
            auth=config[user_key],
        )

        return es

    return get_search



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
            msg = " REQUEST\n%s %s" % (method.upper(), path)
            if data:
                if nd:
                    for item in data.split("\n"):
                        msg += "\n%s" % json.dumps(item, indent=2)
                else:
                    msg += "\n%s" % json.dumps(data, indent=2)
        elif self.request_log_format in ("curl", "cur_req"):
            ct = MIME_NEWLINE_DELIMITED_JSON if nd else MIME_JSON
            msg = " REQUEST\ncurl -v -X %s -H %s %s" % (
                method.upper(),
                f"Content-Type='{ct}; charset=UTF-8'",
                url
            )
            if data:
                msg += "-d '"
                if nd:
                    msg += data
                else:
                    msg += "s" % json.dumps(data, indent=2)
                msg += "'"

        self.request_log.info(msg)


    def log_response(self, response):
        if not self.request_log:
            return

        if "req" in self.request_log_format:
            return

        msg = " RESPONSE %s" % (response.status_code)
        data = response.json()
        if data:
            msg += "\n%s" % json.dumps(data, indent=2)

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
        definition = self._load_definition_object(definition, replace_prefix=True)

        if self.prefix:
            name = f"{self.prefix}-{name}"

        url = f"{self.api_root}/_security/role/{name}"

        self.log_request("put", url)
        response = requests.put(url, json=definition, **self.request_kwargs)
        self.log_response(response)
        if response.status_code != 200:
            LOG.error(query_error(response))
            raise EsException("Failed to put ES role.")
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
        definition = self._load_definition_object(definition, replace_prefix=True)

        name = self.user_name(name)

        url = f"{self.api_root}/_security/user/{name}"

        self.log_request("put", url)
        response = requests.put(url, json=definition, **self.request_kwargs)
        self.log_response(response)
        if response.status_code != 200:
            LOG.error(query_error(response))
            raise EsException("Failed to put ES user.")
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
            text = definition.read_text()
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
        url += "/%d" % document_id

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
                "Failed to create ES index `%s`." % name,
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
                "Failed to delete ES index `%s`." % name,
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
            raise EsException(
                "Failed to index document `%s`." % response.status_code)


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
            raise EsException(
                "Failed to delete document `%s`." % response.status_code)


    def delete_all(
            self,
            index_name: str,
    ) -> None:
        index_name = self._calc_index_name(index_name)
        url = self._calc_url(index_name) + f"/_delete_by_query"

        query = {
            "query": {
                "match_all": {},
            }
        }

        # Create a new index with our index definition
        LOG.info("deleting document.")
        self.log_request("delete", url)
        response = requests.post(url, json=query, **self.request_kwargs)
        self.log_response(response)
        if not str(response.status_code).startswith("2"):
            LOG.error(query_error(response))
            raise EsException(
                "Failed to delete document `%s`." % response.status_code)


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
        user_admin: dict | None = None,
):
    if user_admin:
        definition = {
            "password" : user_admin["password"],
        }
        if user_admin["role"]:
            role = user_admin["role"]
            if es.prefix:
                role = f"{es.prefix}-{role}"
            definition["roles"] = [
                role,
            ]

        es.put_user(user_admin["username"], definition)



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
        "--api-root", "-A",
        type=verify_uri,
        help=f"Elasticsearch api-root. Default: `{DEFAULT_API_ROOT}`.")

    parser.add_argument(
        "--prefix", "-P",
        help="Elasticsearch index name prefix")

    parser.add_argument(
        "--index-name", "-i",
        action="append",
        help="Only work on the supplied indices.")

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



def manage_kwargs(
        args: argparse.Namespace | None = None
):
    kwargs = {}

    if args.api_root is not None:
        kwargs["api_root"] = args.api_root
    if args.prefix is not None:
        kwargs["prefix"] = args.prefix

    return kwargs



def manage_main(
        args: argparse.Namespace,
        roles: dict,
        indices: dict,
        api_root: str | None = None,
        prefix: str | None = None,
        ssl_cert: str | None = None,
        user_admin: dict | None = None,
) -> None:
    es = Es(
        api_root=api_root,
        prefix=prefix,
        ssl_cert=ssl_cert,
        auth="elastic",
    )

    if "delete-indices" in args.command:
        delete_indices(es, indices)

    if "put-roles" in args.command:
        put_roles(es, roles)

    if "put-users" in args.command:
        put_users(es, user_admin)

    if "put-indices" in args.command:
        put_indices(es, indices)
