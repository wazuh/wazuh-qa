# Copyright (C) 2015-2022, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from logging import exception
import os
import re
import json
import yaml
import requests
import urllib3
from elasticsearch import Elasticsearch, helpers

from wazuh_testing.qa_docs import QADOCS_LOGGER
from wazuh_testing.tools.logging import Logging
from wazuh_testing.tools.exceptions import QAValueError


class IndexData:
    """Class that indexes the data from JSON files into ElasticSearch.

    Attributes:
        path (str): A string that contains the path where the parsed documentation is located.
        index (str): A string with the index name to be indexed with Elasticsearch.
        files_format (str): A string with the generated documentation format.
        regex: A regular expression to get JSON files.
        es (ElasticSearch): An `ElasticSearch` client instance.
        output (list): A list to be indexed in Elasticsearch.
    """
    LOGGER = Logging.get_logger(QADOCS_LOGGER)

    def __init__(self, index, path, file_format):
        """Class constructor

        Initialize every attribute.

        Args:
            index (str): Index name.
            path (str): Path where the generated documentation is allocated.
            file_format (str): Generated documentation format.
        """
        self.path = path
        self.index = index
        self.files_format = file_format
        self.regex = re.compile(f".*{file_format}")
        self.es = Elasticsearch()
        self.output = []

    def test_connection(self):
        """Verify with an HTTP request that an OK response is received from ElasticSearch.

        Returns:
            boolean: A boolean with True if the request response is OK.
        """
        try:
            res = requests.get("http://localhost:9200/_cluster/health")
            if res.status_code == 200:
                return True
        except (ConnectionRefusedError, urllib3.exceptions.NewConnectionError, urllib3.exceptions.MaxRetryError,
                requests.exceptions.ConnectionError):
            raise QAValueError(f"Could not connect with ElasticSearch.", IndexData.LOGGER.error) from None

    def get_files(self):
        """Find all the files inside the documentation path that matches with the JSON regex.

        Returns:
            doc_files (list): A list with all the files inside the path.
        """
        doc_files = []

        for (root, *_, files) in os.walk(self.path):
            for file in files:
                if self.regex.match(file):
                    doc_files.append(os.path.join(root, file))

        return doc_files

    def read_files_content(self, files):
        """Open every file found in the path and appends the content into a list.

        Args:
            files (list): A list with the files that matched with the regex.
        """
        if self.files_format == 'json':
            for file in files:
                with open(file, 'r') as module_file:
                    lines = json.load(module_file)
                    self.output.append(lines)
        else:
            for file in files:
                with open(file, 'r') as module_file:
                    lines = yaml.load(module_file, Loader=yaml.FullLoader)
                    self.output.append(lines)

    def remove_index(self):
        """Delete an index."""
        delete = self.es.indices.delete(index=self.index, ignore=[400, 404])
        IndexData.LOGGER.info(f'Deleting the already existing index: {self.index}')

    def run(self):
        """Collect all the documentation files and makes a request to the BULK API to index the new data."""
        if self.test_connection():
            files = self.get_files()
            self.read_files_content(files)

            try:
                if self.es.count(index=self.index):
                    self.remove_index()
            except Exception:
                pass

            IndexData.LOGGER.info("Indexing data")
            helpers.bulk(self.es, self.output, index=self.index)
            out = json.dumps(self.es.cluster.health(wait_for_status='yellow', request_timeout=1), indent=4)
            IndexData.LOGGER.debug(out)
            IndexData.LOGGER.info("The data have been successfully indexed")
