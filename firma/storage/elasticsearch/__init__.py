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
            dump_request=None,
            dump_request_format=None,
            dump_response=None,
    ):

        self.api_root = api_root
        self.index_name = index_name  # Default, may be overridden in member functions
        self.index_prefix = index_prefix

        if dump_request or dump_request_format or dump_response:
            LOG.warning("ES logging functions not implemented.")

        self._bulk_buffer = []


    @property
    def index_endpoint(self):
        return self.api_root + "/" + self.index_name


    def refresh(self, index=None):
        if index is None:
            index = self.index_name

        url = self.api_root
        if self.index_name is not None:
            url += "/" + self.index_name
        url += "/_refresh"

        response = requests.post(url)
        if response.status_code != 200:
            LOG.error(query_error(response))
            raise EsException("Failed to refresh ES node.")
        LOG.debug("OK")


    def _calc_index_name(
            self,
            index_name: [str, None, Default] = Default.INDEX_NAME,
    ) -> Union[str, None]:
        """
        Calculate the index name for member functions.
        It may still be none
        """

        if index_name is Default.INDEX_NAME:
            index_name = self.index_name
        elif (
                index_name and self.index_prefix and
                not index_name.startswith(self.index_prefix + "-")
        ):
            index_name = self.index_prefix + "-" + index_name

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


    def count(
            self,
            index_name: [str, None, Default] = Default.INDEX_NAME,
    ) -> int:
        url = self._calc_url(index_name) + "/_count"

        response = requests.get(url)
        if response.status_code != 200:
            raise EsException("Failed to count documents.", response=response)

        result = response.json()

        print(result)

        return result["count"]


    def search(self, query, index=None):

        if index is None:
            index = self.index_name

        url = self.api_root
        if index is not None:
            url += "/" + index
        url += "/_search"

        response = requests.post(url, json=query)
        if response.status_code != 200:
            LOG.error(query_error(response))
            raise EsException("Failed to search.")

        result = response.json()

        return result


    def document(self, document_id, index=None):

        if index is None:
            index = self.index_name

        url = self.api_root
        if index is not None:
            url += "/" + index
        url += "/%d" % document_id

        response = requests.get(url)
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
        response = requests.put(url, json=definition)
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
        response = requests.delete(url)
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
        response = requests.request(method, url, json=document)
        if not str(response.status_code).startswith("2"):
            LOG.error(query_error(response))
            raise EsException(
                "Failed to index document `%s`." % response.status_code)


    def delete(
            self,
            index=None,
            id_=None
    ) -> None:
        if index is None:
            index = self.index_name

        url = self.api_root
        if index is not None:
            url += "/" + index

        url += "/%s/%s" % ("_doc", str(id_))

        # Create a new index with our index definition
        LOG.info("deleting document.")
        response = requests.delete(url)
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

        response = requests.get(url)
        if response.status_code != 200:
            print(response.json())
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
                action_data["_index"] = index_name

        if id_ is not None:
                action_data["_id"] = id_

        self._bulk_buffer += [action_data, document]

        if auto and len(self._bulk_buffer) > CHUNK_SIZE_DOCS:
            self.bulk()



    def bulk(
            self,
            index_name: [str, None, Default] = Default.INDEX_NAME,
    ) -> JsonObject:

        index_name = self._calc_index_name(index_name)
        url = self._calc_url(index_name) + "/_bulk"

        payload = "".join([json.dumps(v) + "\n" for v in self._bulk_buffer])
        payload_length_doc = len(self._bulk_buffer) / 2
        payload_length_mem = len(payload)
        self._bulk_buffer = []

        LOG.debug(
            "ES bulk insert of %d records, ~%s bytes",
            payload_length_doc, humanize.naturalsize(payload_length_mem, binary=True))
        response = requests.post(url, data=payload, headers={
            "content-type": "application/x-ndjson"
        })
        if response.status_code != 200:
            LOG.error(query_error(response))
            raise EsException("Bulk action failed.")
        result = response.json()
        if result["errors"]:
            LOG.error(query_error(response))
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
                n = es.count(index_name=name)
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
            LOG.warning("".join(ndiff))
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
