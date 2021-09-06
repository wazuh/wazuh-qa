"""
brief: Wazuh DocGenerator data indexer.
copyright: Copyright (C) 2015-2021, Wazuh Inc.
date: August 04, 2021
license: This program is free software; you can redistribute it
         and/or modify it under the terms of the GNU General Public
         License (version 2) as published by the FSF - Free Software Foundation.
"""

import os
import re
import json
import requests
import logging
from elasticsearch import Elasticsearch, helpers


class IndexData:
    """
    brief: Class that indexes the data from JSON files into ElasticSearch.
    """
    def __init__(self, index, config):
        self.path = config.documentation_path
        self.index = index
        self.regex = re.compile(".*json")
        self.es = Elasticsearch()
        self.output = []

    def test_connection(self):
        """
        brief: It verifies with an HTTP request that an OK response is received from ElasticSearch.
        """
        try:
            res = requests.get("http://localhost:9200/_cluster/health")
            if res.status_code == 200:
                return True
        except Exception as e:
            logging.exception(f"Connection error:\n{e}")
            return False

    def get_files(self):
        """
        brief: Finds all the files inside the documentation path that matches with doc_file_regex.
        """
        doc_files = []
        for (root, *_, files) in os.walk(self.path):
            for file in files:
                if self.regex.match(file):
                    doc_files.append(os.path.join(root, file))
        return doc_files

    def read_files_content(self, files):
        """
        brief: Opens every file found in the path and appends the content into a list.
        """
        for file in files:
            with open(os.path.join(self.path, file)) as f:
                lines = json.load(f)
                self.output.append(lines)

    def remove_index(self):
        """
        brief: Deletes an index.
        """
        delete = self.es.indices.delete(index=self.index, ignore=[400, 404])
        logging.info(f'Delete index {self.index}\n {delete}\n')

    def run(self):
        """
        brief: Collects all the documentation files and makes a request to the BULK API to index the new data.
        """
        self.test_connection()
        files = self.get_files()
        self.read_files_content(files)
        if self.test_connection():
            self.remove_index()
            logging.info("Indexing data...\n")
            helpers.bulk(self.es, self.output, index=self.index)
            out = json.dumps(self.es.cluster.health(wait_for_status='yellow', request_timeout=1), indent=4)
            logging.info(out)
