import json
import logging
from io import IOBase
from urllib.parse import urlunparse

import requests



DEFAULT_ELASTICSEARCH_SCHEME = "http"
DEFAULT_ELASTICSEARCH_HOST = "localhost"
DEFAULT_ELASTICSEARCH_PORT = 9200



class ElasticsearchException(Exception):
    pass



LOG = logging.getLogger('elasticsearch')



def query_error(response):
    return json.dumps(response.json(), sort_keys=True, indent=2)



# Elasticsearch Functions



class Elasticsearch():

    def __init__(
            self,
            scheme=None,
            host=None,
            port=None,
            index=None,
            dump_request=None,
            dump_request_format=None,
            dump_response=None,
    ):
        scheme = scheme or DEFAULT_ELASTICSEARCH_SCHEME
        host = host or DEFAULT_ELASTICSEARCH_HOST
        port = port or DEFAULT_ELASTICSEARCH_PORT

        if dump_request or dump_request_format or dump_response:
            LOG.warning("ES logging functions not implemented.")

        self.root = urlunparse((
            scheme,
            host + (":%d" % port if port else ""),
            "",
            None,
            None,
            None,
        ))
        self.index_name = index

        self._bulk_buffer = []


    def refresh(self, index=None):
        if index is None:
            index = self.index_name

        url = self.root
        if self.index_name is not None:
            url += "/" + self.index_name
        url += "/_refresh"

        response = requests.post(url)
        if response.status_code != 200:
            LOG.error(query_error(response))
            raise ElasticsearchException("Failed to refresh ES node.")
        LOG.debug("OK")


    def count(self, index=None):
        "Returns an integer."

        if index is None:
            index = self.index_name

        url = self.root
        if index is not None:
            url += "/" + index
        url += "/_count"

        response = requests.post(url)
        if response.status_code != 200:
            LOG.error(query_error(response))
            raise ElasticsearchException("Failed to count documents.")

        result = response.json()

        return result["count"]


    def search(self, query, index=None):

        if index is None:
            index = self.index_name

        url = self.root
        if index is not None:
            url += "/" + index
        url += "/_search"

        response = requests.post(url, json=query)
        if response.status_code != 200:
            LOG.error(query_error(response))
            raise ElasticsearchException("Failed to search.")

        result = response.json()

        return result


    def document(self, document_id, index=None):

        if index is None:
            index = self.index_name

        url = self.root
        if index is not None:
            url += "/" + index
        url += "/%d" % document_id

        response = requests.get(url)
        if response.status_code != 200:
            LOG.error(query_error(response))
            raise ElasticsearchException("Failed to search.")

        result = response.json()

        result.update({
            "id": document_id
        })

        return result


    def create_index(self, definition, index=None):
        """
        `definition` may be an object, path, or file.
        """

        if isinstance(definition, str):
            with open(definition, "r") as fp:
                definition = json.load(fp)
        elif isinstance(definition, IOBase):
            definition = json.load(definition)

        if index is None:
            index = self.index_name

        url = self.root + "/" + index

        # If a index with the same name alread exists, delete it.
        LOG.info("Deleting ES index `%s`.", index)
        response = requests.delete(url)
        if response.status_code == 404:
            LOG.debug("ES index `%s` did not exist", index)
        elif response.status_code != 200:
            LOG.error(query_error(response))
            raise ElasticsearchException(
                "Failed to delete ES index `%s`." % index)
        LOG.debug("OK")

        # Create a new index with our index definition
        LOG.info("Creating Elasticsearch index '%s'.", index)
        response = requests.put(url, json=definition)
        if response.status_code != 200:
            LOG.error(query_error(response))
            raise ElasticsearchException(
                "Failed to create ES index `%s`." % index)

        LOG.debug("OK")


    def index(self, document, index=None, id_=None):
        if index is None:
            index = self.index_name

        url = self.root
        if index is not None:
            url += "/" + index

        if id_ is None:
            method = "post"
        else:
            method = "put"
            url += "/%s/%s" % ("_doc", str(id_))

        # Create a new index with our index definition
        LOG.info("Indexing document.")
        response = requests.request(method, url, json=document)
        if not str(response.status_code).startswith("2"):
            LOG.error(query_error(response))
            raise ElasticsearchException(
                "Failed to index document `%s`." % response.status_code)


    def delete(self, index=None, id_=None):
        if index is None:
            index = self.index_name

        url = self.root
        if index is not None:
            url += "/" + index

        url += "/%s/%s" % ("_doc", str(id_))

        # Create a new index with our index definition
        LOG.info("deleting document.")
        response = requests.delete(url)
        if not str(response.status_code).startswith("2"):
            LOG.error(query_error(response))
            raise ElasticsearchException(
                "Failed to delete document `%s`." % response.status_code)


    def bulk_queue_index(self, document, meta):
        # Only one document type is allowed from ES 6.0 onwards
        # https://www.elastic.co/guide/en/elasticsearch/reference/master/removal-of-types.html#_schedule_for_removal_of_mapping_types
        meta.update({
            "_type": "_doc"
        })

        self._bulk_buffer += [{
            "index": meta
        }, document]


    def bulk_execute(self, index=None):
        "Returns a result object."

        if index is None:
            index = self.index_name

        url = self.root
        if index is not None:
            url += "/" + index
        url += "/_bulk"

        payload = "".join([json.dumps(v) + "\n" for v in self._bulk_buffer])
        payload_length = len(self._bulk_buffer)
        self._bulk_buffer = []

        LOG.debug("ES bulk insert of %d records", payload_length)
        response = requests.post(url, data=payload, headers={
            "content-type": "application/x-ndjson"
        })
        if response.status_code != 200:
            LOG.error(query_error(response))
            raise ElasticsearchException("Bulk action failed.")
        result = response.json()
        if result["errors"]:
            LOG.error(query_error(response))
            raise ElasticsearchException("Some bulk actions failed.")

        return result
