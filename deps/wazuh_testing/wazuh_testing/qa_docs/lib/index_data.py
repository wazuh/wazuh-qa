# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import re
import json
import requests
from elasticsearch import Elasticsearch, helpers

from wazuh_testing.qa_docs import QADOCS_LOGGER
from wazuh_testing.tools.logging import Logging
from wazuh_testing.tools.exceptions import QAValueError


class IndexData:
    """Class that indexes the data from JSON files into ElasticSearch.

    Attributes:
        path: A string that contains the path where the parsed documentation is located.
        index: A string with the index name to be indexed with Elasticsearch.
        regex: A regular expression to get JSON files.
        es: An `ElasticSearch` client instance.
        output: A list to be indexed in Elasticsearch.
    """
    LOGGER = Logging.get_logger(QADOCS_LOGGER)

    def __init__(self, index, config):
        """Class constructor

        Initialize every attribute.

        Args:
            config: A `Config` instance with the loaded data from config file.
        """
        self.path = config.documentation_path
        self.index = index
        self.regex = re.compile(".*json")
        self.es = Elasticsearch()
        self.output = []

    def test_connection(self):
        """Verify with an HTTP request that an OK response is received from ElasticSearch."""
        try:
            res = requests.get("http://localhost:9200/_cluster/health")
            if res.status_code == 200:
                return True
        except Exception as exception:
            raise QAValueError(f"Connection error: {exception}", IndexData.LOGGER.error)

    def get_files(self):
        """Find all the files inside the documentation path that matches with the JSON regex."""
        doc_files = []

        for (root, *_, files) in os.walk(self.path):
            for file in files:
                if self.regex.match(file):
                    doc_files.append(os.path.join(root, file))

        return doc_files

    def read_files_content(self, files):
        """Open every file found in the path and appends the content into a list.

        Args:
            files: A list with the files that matched with the regex.
        """
        for file in files:
            with open(file) as test_file:
                lines = json.load(test_file)
                self.output.append(lines)

    def remove_index(self):
        """Deletes an index."""
        delete = self.es.indices.delete(index=self.index, ignore=[400, 404])
        IndexData.LOGGER.info(f'Delete index {self.index}\n {delete}\n')

    def run(self):
        """Collects all the documentation files and makes a request to the BULK API to index the new data."""
        self.test_connection()
        files = self.get_files()
        self.read_files_content(files)

        if self.test_connection():
            self.remove_index()
            IndexData.LOGGER.info("Indexing data...\n")
            helpers.bulk(self.es, self.output, index=self.index)
            out = json.dumps(self.es.cluster.health(wait_for_status='yellow', request_timeout=1), indent=4)
            IndexData.LOGGER.info(out)
