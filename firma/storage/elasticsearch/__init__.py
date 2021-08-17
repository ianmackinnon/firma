import sys
import enum
import json
import logging
import argparse
from io import IOBase
from difflib import ndiff
from typing import Union, Callable
from pathlib import Path
from urllib.parse import urlparse, urlunparse

import humanize
import requests

from firma.util import load_conf



DEFAULT_API_ROOT = "http://localhost:9200"
CHUNK_SIZE_DOCS = 2**8
MIME_JSON = "application/json"
MIME_NEWLINE_DELIMITED_JSON = "application/x-ndjson"


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



# Defaults for functions where `None` can't be the default.

@enum.unique
class Default(enum.Enum):
    INDEX_NAME = enum.auto()



LOG = logging.getLogger('elasticsearch')



def query_error(response):
    return json.dumps(response.json(), sort_keys=True, indent=2)



def get_conf_defaults(path: Path) -> dict:
    config = load_conf(path)
    if "elasticsearch" not in config:
        raise Exception(
            f"Section `elasticsearch` is required but not present in configuration file {str(path)}.")

    api_root = config["elasticsearch"].get("api-root", DEFAULT_API_ROOT)
    api_root = verify_uri(api_root)

    data = {
        "api_root": api_root,
    }

    if "index-prefix" in config["elasticsearch"]:
        data["index_prefix"] = config["elasticsearch"]["index-prefix"]

    return data



def get_conf(args: argparse.Namespace, defaults: dict) -> dict:
    api_root = args.api_root or defaults["api_root"]
    index_prefix = args.prefix or defaults.get("index_prefix", None)

    assert index_prefix

    return {
        "api_root": api_root,
        "index_prefix": index_prefix,
    }



# Es Functions



class Es():
    """
    Controller for Elasticsearch indices.

    A default index name may be supplied.
    """

    def __init__(
            self,
            api_root: [str, None] = None,
            index_prefix: [str, None] = None,
            index_name: [str, None] = None,
            request_log: [logging.Logger, None] = None,
            request_log_format: [str, None] = None,
    ):

        self.api_root = api_root
        self.index_name = index_name  # Default, may be overridden in member functions
        self.index_prefix = index_prefix

        self.request_log = request_log
        self.request_log_format = request_log_format
        if self.request_log_format is None:
            self.request_log_format = "console_req"

        self._bulk_buffer = []


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


    def _calc_index_name(
            self,
            index_name: [str, None, Default] = Default.INDEX_NAME,
    ) -> Union[str, None]:
        """
        Calculate the index name for member functions.
        It may still be none

        Index name may be a comma separated string.
        """

        if index_name is Default.INDEX_NAME:
            index_name = self.index_name

        if index_name and self.index_prefix:
            index_name = ",".join([
                v if v.startswith(self.index_prefix + "-")
                else self.index_prefix + "-" + v
                for v in index_name.split(",")
            ])

        return index_name


    def _calc_url(
            self,
            index_name: [str, None, Default] = Default.INDEX_NAME,
    ) -> str:
        index_name = self._calc_index_name(index_name)

        url = self.api_root
        if index_name is not None:
            url += "/" + index_name

        return url

    @staticmethod
    def _load_definition_object(
            definition: Union[str, Path, IOBase, dict],
    ):
        if isinstance(definition, str):
            definition = Path(definition)
        if isinstance(definition, Path):
            with definition.open() as fp:
                definition = json.load(fp)
        if isinstance(definition, IOBase):
            definition = json.load(definition)

        assert isinstance(definition, dict)

        return definition


    def refresh(
            self,
            index_name: [str, None, Default] = Default.INDEX_NAME,
    ) -> None:

        index_name = self._calc_index_name(index_name)
        url = self._calc_url(index_name) + "/_refresh"

        self.log_request("post", url)
        response = requests.post(url)
        self.log_response(response)
        if response.status_code != 200:
            LOG.error(query_error(response))
            raise EsException("Failed to refresh ES node.")
        LOG.debug("OK")


    def count(
            self,
            index_name: [str, None, Default] = Default.INDEX_NAME,
    ) -> int:
        url = self._calc_url(index_name) + "/_count"

        self.log_request("post", url)
        response = requests.post(url)
        self.log_response(response)
        if response.status_code != 200:
            raise EsException("Failed to count documents.", response=response)

        result = response.json()

        return result["count"]


    def search(
            self,
            query,
            index_name: [str, None, Default] = Default.INDEX_NAME,
    ):

        index_name = self._calc_index_name(index_name)
        url = self._calc_url(index_name) + "/_search"

        self.log_request("post", url, query)
        response = requests.post(url, json=query)
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
        response = requests.get(url)
        self.log_response(response)
        if response.status_code != 200:
            LOG.error(query_error(response))
            raise EsException("Failed to search.")

        result = response.json()

        result.update({
            "id": document_id
        })

        return result


    def create_index(
            self,
            definition: Union[str, Path, IOBase, dict],
            index_name: [str, None, Default] = Default.INDEX_NAME,
    ):
        index_name = self._calc_index_name(index_name)
        definition = self._load_definition_object(definition)

        url = self._calc_url(index_name)

        self.delete_index(index_name)

        # Create a new index with our index definition
        LOG.info("Creating ES index '%s'.", index_name)
        self.log_request("put", url, definition)
        response = requests.put(url, json=definition)
        self.log_response(response)
        if response.status_code != 200:
            LOG.error(query_error(response))
            raise EsException(
                "Failed to create ES index `%s`." % index_name,
                response=response)
        LOG.info("Created ES index `%s`.", index_name)


    def delete_index(
            self,
            index_name: [str, None, Default] = Default.INDEX_NAME,
    ) -> None:
        """
        Attempt to delete index.
        """
        index_name = self._calc_index_name(index_name)
        url = self._calc_url(index_name)

        # If a index with the same name alread exists, delete it.
        LOG.info("Deleting ES index `%s`.", index_name)
        self.log_request("delete", url)
        response = requests.delete(url)
        self.log_response(response)
        if response.status_code == 404:
            LOG.debug("ES index `%s` did not exist.", index_name)
        elif response.status_code != 200:
            LOG.error(query_error(response))
            raise EsException(
                "Failed to delete ES index `%s`." % index_name,
                response=response)
        else:
            LOG.info("Deleted ES index `%s`.", index_name)


    def index(
            self,
            document,
            index_name: [str, None, Default] = Default.INDEX_NAME,
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
        response = requests.request(method, url, json=document)
        self.log_response(response)
        if not str(response.status_code).startswith("2"):
            LOG.error(query_error(response))
            raise EsException(
                "Failed to index document `%s`." % response.status_code)


    def delete(
            self,
            index_name: [str, None, Default] = Default.INDEX_NAME,
            id_=None
    ) -> None:
        index_name = self._calc_index_name(index_name)
        url = self._calc_url(index_name) + f"/_doc/{str(id_)}"

        # Create a new index with our index definition
        LOG.info("deleting document.")
        self.log_request("delete", url)
        response = requests.delete(url)
        self.log_response(response)
        if not str(response.status_code).startswith("2"):
            LOG.error(query_error(response))
            raise EsException(
                "Failed to delete document `%s`." % response.status_code)


    def mapping(
            self,
            index_name: [str, None, Default] = Default.INDEX_NAME,
    ) -> JsonObject:
        index_name = self._calc_index_name(index_name)
        url = self._calc_url(index_name) + "/_mapping"

        self.log_request("get", url)
        response = requests.get(url)
        self.log_response(response)
        if response.status_code != 200:
            raise EsException("Failed to retrieve mapping.", response=response)

        result = response.json()

        if index_name:
            return result[index_name]

        return result


    def index_queue(
            self,
            document,
            index_name: [str, None, Default] = Default.INDEX_NAME,
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
            self.bulk()


    def delete_queue(
            self,
            index_name: [str, None, Default] = Default.INDEX_NAME,
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
            self.bulk()


    def bulk(
            self,
            index_name: [str, None, Default] = Default.INDEX_NAME,
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
        })
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



def create_indices(
        es: Es,
        indices: dict,
        force: Union[bool, None],
):
    """
    Recreate indices if they don't exist or if `force` is truthy.

    `indices` is a dict of `{name: definition}`.
    """

    create = force
    if not create:
        for name, definition in indices.items():
            try:
                es.count(index_name=name)
            except EsException as e:
                if e.type == "index_not_found_exception":
                    create = True
                    break

    if not create:
        return

    for name, definition in indices.items():
        es.create_index(definition, index_name=name)



def delete_indices(
        es: Es,
        indices: dict,
):
    for name in indices:
        es.delete_index(index_name=name)



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



# Management parser and main



def verify_uri(text: str) -> str:
    return urlunparse(urlparse(text))



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
        default="http://localhost:9200",
        type=verify_uri,
        help="Elasticsearch api-root. Default: `{DEFAULT_API_ROOT}`.")

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
        help="One of `create`, `insert`, `build`, `update`, `delete`, `compare`.")

    # Insert documents if any of the following are specified
    return parser



def manage_main(
        args: argparse.Namespace,
        indices: dict,
        insert_documents: Callable,
        api_root: Union[str, None] = None,
        index_prefix: Union[str, None] = None,
) -> None:
    indices = indices.copy()
    if args.index_name:
        indices = {k: v for k, v in indices.items() if k in args.index_name}

    es = Es(api_root=api_root, index_prefix=index_prefix)

    if args.command == "delete":
        delete_indices(es, indices)
        return

    if args.command == "update":
        raise NotImplementedError()

    if args.command == "compare":
        if compare_indices(es, indices):
            sys.exit(1)
        return

    if args.command in ("create", "build"):
        create_indices(es, indices, force=True)

    if args.command in ("build", "insert"):
        insert_documents(es, args, indices)
