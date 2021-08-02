"""
brief: Wazuh DocGenerator tool.
copyright: Copyright (C) 2015-2021, Wazuh Inc.
date: August 02, 2021
license: This program is free software; you can redistribute it
         and/or modify it under the terms of the GNU General Public
         License (version 2) as published by the FSF - Free Software Foundation.
"""

import os
import re
import json
import yaml
import ast
from Config import Config
from CodeParser import CodeParser
from Sanity import Sanity
from Utils import clean_folder
import warnings
import logging
import argparse

VERSION = "0.1"

class DocGenerator:
    """
    brief: Main class of DocGenerator tool.
    It´s in charge of walk every test file, and every group file to dump the parsed documentation
    """
    def __init__(self):
        self.conf = Config()
        self.parser = CodeParser()
        self.__id_counter = 0
        self.ignore_regex = []
        for ignore_regex in self.conf.ignore_paths:
            self.ignore_regex.append(re.compile(ignore_regex))
        self.include_regex = []
        for include_regex in self.conf.include_regex:
            self.include_regex.append(re.compile(include_regex))

    def is_valid_folder(self, path):
        """
        brief: Checks if a path should be ignored because its in the ignore list.
        args: -"path (str): Folder location to be controlled"
        returns: "boolean: False if the path should be ignored. True otherwise."
        """
        for regex in self.ignore_regex:
            if regex.match(path):
                return False
        return True

    def is_valid_file(self, path):
        """
        brief: Checks if a file path should be ignored because its in the ignore list or doesn´t match with the regexes.
        args: -"path (str): File location to be controlled"
        returns: "boolean: False if the path should be ignored. True otherwise."
        """
        for regex in self.ignore_regex:
            if regex.match(path):
                return False
        for regex in self.include_regex:
            match = False
            if regex.match(path):
                match = True
                break
        if not match:
            return False
        return True

    def is_group_file(self, path):
        """
        brief: Checks if a file path should be considered as a file containing group information.
        args: -"path (str): File location to be controlled"
        returns: "boolean: True if the file is a group file. False otherwise."
        """
        for group_file in self.conf.group_files:
            if path == group_file:
                return True
        return False

    def get_group_doc_path(self):
        """
        brief: Returns the name of the group file in the documentation output based on the original file name.
        returns: "string: The name of the documentation group file"
        """
        base_path = os.path.join(self.conf.documentation_path, os.path.basename(self.scan_path))
        group_name = os.path.basename(self.scan_path)
        doc_path = os.path.join(base_path,group_name+".group")
        return doc_path

    def get_test_doc_path(self, path):
        """
        brief: Returns the name of the test file in the documentation output based on the original file name.
        args: -"path (str): The original file name"
        returns: "string: The name of the documentation test file"
        """
        base_path = os.path.join(self.conf.documentation_path, os.path.basename(self.scan_path))
        relative_path = path.replace(self.scan_path, "")
        doc_path = os.path.splitext(base_path + relative_path)[0]
        return doc_path

    def dump_output(self, content, doc_path):
        """
        brief: Creates a JSON and a YAML file with the parsed content of a test module.
        It also creates the containing folder if it doesn´t exists.
        args:
            - "content (dict): The parsed content of a test file."
            - "doc_path (string): The path where the information should be dumped."
        """
        if not content:
            warnings.warn(f"Content for {doc_path} is empty, ignoring it", stacklevel=2)
            logging.warning(f"Content for {doc_path} is empty, ignoring it")
            return
        if not os.path.exists(os.path.dirname(doc_path)):
            os.makedirs(os.path.dirname(doc_path))
        with open(doc_path + ".json", "w+") as outfile:
            outfile.write(json.dumps(content, indent=4))
        with open(doc_path + ".yaml", "w+") as outfile:
            outfile.write(yaml.dump(content))

    def create_group(self, path, group_id):
        """
        brief: Parses the content of a group file and dumps the content into a file.
        args:
            - "path (string): The path of the group file to be parsed."
            - "group_id (string): The id of the group where the new group belongs."
        return "integer: The ID of the new generated group document.
        """
        self.__id_counter = self.__id_counter + 1
        group = self.parser.parse_group(path, self.__id_counter, group_id)
        doc_path = self.get_group_doc_path()
        self.dump_output(group, doc_path)
        logging.debug(f"New group file '{doc_path}' was created with ID:{self.__id_counter}")
        return self.__id_counter

    def create_test(self, path, group_id):
        """
        brief: Parses the content of a test file and dumps the content into a file.
        args:
            - "path (string): The path of the test file to be parsed."
            - "group_id (string): The id of the group where the new test belongs."
        return "integer: The ID of the new generated test document.
        """
        self.__id_counter = self.__id_counter + 1
        test = self.parser.parse_test(path, self.__id_counter, group_id)
        doc_path = self.get_test_doc_path(path)
        self.dump_output(test, doc_path)
        logging.debug(f"New documentation file '{doc_path}' was created with ID:{self.__id_counter}")
        return self.__id_counter

    def parse_folder(self, path, group_id):
        """
        brief: Search in a specific folder to parse possible group files and each test file
        args:
            - "path (string): The path of the folder to be parsed."
            - "group_id (string): The id of the group where the new elements belong."
        """
        if not os.path.exists(path):
            warnings.warn(f"Include path '{path}' doesn´t exist", stacklevel=2)
            logging.warning(f"Include path '{path}' doesn´t exist")
            return
        if not self.is_valid_folder(path):
            logging.debug(f"Ignoring files on '{path}'")
            return
        (root, folders, files) = next(os.walk(path))
        for file in files:
            if self.is_group_file(file):
                group_id = self.create_group(os.path.join(root,file), group_id)
                break
        for file in files:
            if self.is_valid_file(file):
                self.create_test(os.path.join(root,file), group_id)
        for folder in folders:
            self.parse_folder(os.path.join(root,folder), group_id)

    def run(self):
        """
        brief: Run a complete scan of each include path to parse every test and group found.
        """
        logging.info("\nStarting documentation parsing")
        clean_folder(self.conf.documentation_path)
        for path in self.conf.include_paths:
            self.scan_path = path
            logging.debug(f"Going to parse files on '{path}'")
            self.parse_folder(path, self.__id_counter)

def start_logging(folder, debug_level=logging.INFO):
    LOG_PATH = os.path.join(folder, os.path.splitext(os.path.basename(__file__))[0]+".log" )
    if not os.path.exists(folder):
        os.makedirs(folder)
    logging.basicConfig(filename=LOG_PATH, level=debug_level)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', help="Run a sanity check", action='store_true', dest='sanity')
    parser.add_argument('-v', help="Print version", action='store_true', dest="version")
    parser.add_argument('-t', help="Test configuration", action='store_true', dest='test_config')
    parser.add_argument('-d', help="Enable debug messages.", action='count', dest='debug_level')
    args = parser.parse_args()

    if args.debug_level:
        start_logging("logs", logging.DEBUG)
    else:
        start_logging("logs")

    if args.version:
        print(f"DocGenerator v{VERSION}")
    elif args.test_config:
        conf = Config()
    elif args.sanity:
        sanity = Sanity()
        sanity.run()
    else:
        docs = DocGenerator()
        docs.run()
