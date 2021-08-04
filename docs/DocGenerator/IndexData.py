"""
brief: Wazuh DocGenerator config parser.
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
from elasticsearch import Elasticsearch, helpers
from Config import Config

class IndexData:
    """
    brief: Class that indexes the data from JSON files into ElasticSearch.
    """
    def __init__(self, index):
        self.conf = Config()
        self.path = self.conf.documentation_path
        self.index = index
        self.regex = ".*json"
        self.files = self.get_files()
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
            print(e)
            return False

    def get_files(self):
        """
        brief: Recursively finds all the files that match with the regex provided.
        """
        doc_files = []
        r = re.compile(self.regex)
        for (root, *_, files) in os.walk(self.path):
            for file in files:
                if r.match(file):
                    doc_files.append(os.path.join(root,file))
        return doc_files

    def read_files_content(self):
        """
        brief: It Opens every file found in the path and appends the content into a list.
        """
        for file in self.files:
            with open(os.path.join(self.path, file)) as f:
                lines = json.load(f)
                self.output.append(lines)

    def remove_index(self):
        """
        brief: It Deletes an index.
        """
        delete=self.es.indices.delete(index=self.index, ignore=[400, 404])
        print(f'Delete index {self.index}\n {delete}\n')

    def run(self):
        """
        brief: This calls all the methods of the Class. Finally, it uses the index name and the documents
        to make a request to the BULK API.
        """
        self.test_connection()
        self.read_files_content()
        if self.test_connection():
            self.remove_index()
            print("Indexing data...\n")
            helpers.bulk(self.es, self.output, index=self.index)
            out=json.dumps(self.es.cluster.health(wait_for_status='yellow', request_timeout=1), indent=4)
            print(out)

