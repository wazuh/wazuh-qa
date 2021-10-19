# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import re
import json
import yaml

from wazuh_testing.qa_docs.lib.config import Mode
from wazuh_testing.qa_docs.lib.code_parser import CodeParser
from wazuh_testing.qa_docs.lib.utils import clean_folder
from wazuh_testing.qa_docs import QADOCS_LOGGER
from wazuh_testing.tools.logging import Logging
from wazuh_testing.tools.exceptions import QAValueError


class DocGenerator:
    """Main class of DocGenerator tool.

    It is in charge of walk every test file, and every group file to dump the parsed documentation.
    Every folder is checked so they are ignored when the path matches. Then, every test from folders not ignored
    that matches a include regex, is parsed.

    The included paths are generated using the types and modules from the wazuh-qa framework.

    Attributes:
        conf (Config): A `Config` instance with the loaded configuration.
        parser (CodeParser): A `CodeParser` instance with parsing utilities.
        __id_counter (int): An integer that counts the test/group ID when it is created.
        ignore_regex (list): A list with compiled paths to be ignored.
        include_regex (list): A list with regular expressions used to parse a file or not.
    """
    LOGGER = Logging.get_logger(QADOCS_LOGGER)

    def __init__(self, config):
        """Class constructor

        Initialize every attribute.

        Args:
            config (Config): A `Config` instance with the loaded configuration.
        """
        self.conf = config
        self.parser = CodeParser(self.conf)
        self.__id_counter = 0
        self.ignore_regex = []
        for ignore_regex in self.conf.ignore_paths:
            self.ignore_regex.append(re.compile(ignore_regex.replace('\\', '/')))
        self.include_regex = []
        if self.conf.mode == Mode.DEFAULT:
            for include_regex in self.conf.include_regex:
                self.include_regex.append(re.compile(include_regex.replace('\\', '/')))

    def is_valid_folder(self, path):
        """Check if a folder is included so it would be parsed.

        That happens when is not ignored using the ignore list.

        Args:
            path (str): A string that contains the folder location to be controlled

        Return:
            boolean: A boolean with False if the path should be ignored. True otherwise.
        """
        for regex in self.ignore_regex:
            if regex.match(path):
                DocGenerator.LOGGER.debug(f"Ignoring path: {regex} matching with {path}")
                return False

        return True

    def is_valid_file(self, file):
        """Check if a path file is included.

        Also, that file could be ignored(because it is in the ignore list or does not match with the regexes).

        Args:
            file (str): A string that contains the file name to be checked.

        Returns:
            boolean: A boolean with True when matches with an include regex. False if the file should be ignored
            (because it matches with an ignore path or does not match with any include regular expression).
        """
        for regex in self.ignore_regex:
            if regex.match(file):
                DocGenerator.LOGGER.debug(f"Ignoring file: {regex} matching with {file}")
                return False

        for regex in self.include_regex:
            if regex.match(file):
                DocGenerator.LOGGER.debug(f"Including file: {regex} matching with {file}")
                return True

        return False

    def is_group_file(self, path):
        """Check if a file path should be considered as a file containing group information.

        Args:
            path (str): A string that contains the file name to be checked

        Returns:
            boolean: A boolean with True if the file is a group file. False otherwise."
        """
        for group_file in self.conf.group_files:
            if path == group_file:
                return True

        return False

    def get_group_doc_path(self, group):
        """Get the name of the group file in the documentation output based on the original file name.

        Returns:
            doc_path (str): A string that contains the name of the documentation group file.
        """
        base_path = os.path.join(self.conf.documentation_path, os.path.basename(self.scan_path))
        doc_path = os.path.join(base_path, group['name']+".group")

        return doc_path

    def get_test_doc_path(self, path):
        """Get the name of the test file in the documentation output based on the original file name.

        Args:
            path (str): A string that contains the original file name.

        Returns:
            doc_path (str): A string with the name of the documentation test file.
        """
        base_path = os.path.join(self.conf.documentation_path, os.path.basename(self.scan_path))
        relative_path = path.replace(self.scan_path, "")
        doc_path = os.path.splitext(base_path + relative_path)[0]

        return doc_path

    def dump_output(self, content, doc_path):
        """Create a JSON and a YAML file with the parsed content of a test module.

        Also, create the containing folder if it does not exist.

        Args:
            content (dict): A dict that contains the parsed content of a test file.
            doc_path (str): A string with the path where the information should be dumped.

        Raises:
            QAValueError: Cannot write in {doc_path}.json
            QAValueError: Cannot write in {doc_path}.yaml
        """
        if not os.path.exists(os.path.dirname(doc_path)):
            DocGenerator.LOGGER.debug('Creating documentation folder')
            os.makedirs(os.path.dirname(doc_path))

        DocGenerator.LOGGER.debug(f"Writing {doc_path}.json")

        try:
            with open(f"{doc_path}.json", 'w+') as out_file:
                out_file.write(f"{json.dumps(content, indent=4)}\n")
        except IOError:
            raise QAValueError(f"Cannot write in {doc_path}.json", DocGenerator.LOGGER.error)

        DocGenerator.LOGGER.debug(f"Writing {doc_path}.yaml")

        try:
            with open(doc_path + ".yaml", "w+") as out_file:
                out_file.write(yaml.dump(content))
        except IOError:
            raise QAValueError(f"Cannot write in {doc_path}.yaml", DocGenerator.LOGGER.error)

    def create_group(self, path, group_id):
        """Parse the content of a group file and dump the content into a file.

        Args:
            path (str): A string with the path of the group file to be parsed.
            group_id (str): A string with the id of the group where the new group belongs.

        Returns:
            __id.counter (int): An integer with the ID of the newly generated group document.
            None if the test does not have documentation.
        """
        self.__id_counter = self.__id_counter + 1
        group = self.parser.parse_group(path, self.__id_counter, group_id)

        if group:
            doc_path = self.get_group_doc_path(group)
            self.dump_output(group, doc_path)
            DocGenerator.LOGGER.debug(f"New group file '{doc_path}' was created with ID:{self.__id_counter}")
            return self.__id_counter
        else:
            DocGenerator.LOGGER.warning(f"Content for {path} is empty, ignoring it")
            return None

    def create_test(self, path, group_id, test_name=None):
        """Parse the content of a test file and dumps the content into a file.

        Modes:
            Single test:
                When a single test is going to be parsed, if it has not an output directory, the content is printed.
                If it has an output dir, the content is dumped into that dir.

            Default:
                The content is dumped into the corresponding directory.

        Args:
            path (str): A string with the path of the test file to be parsed.
            group_id (str): A string with the id of the group where the new test belongs.
            test_name (str): A string with the name of the test that is going to be parsed.

        Returns:
            __id.counter (int): An integer with the ID of the new generated test document.
            None if the test does not have documentation.
        """
        self.__id_counter = self.__id_counter + 1
        test = self.parser.parse_test(path, self.__id_counter, group_id)

        if test:
            if self.conf.mode == Mode.DEFAULT:
                doc_path = self.get_test_doc_path(path)

            elif self.conf.mode == Mode.PARSE_TESTS:
                doc_path = self.conf.documentation_path

                # If the user does not specify an output dir
                if not doc_path:
                    self.print_test_info(test)
                    return
                # If the user specifies an output dir
                else:
                    doc_path = os.path.join(doc_path, test_name)

            self.dump_output(test, doc_path)
            DocGenerator.LOGGER.debug(f"New documentation file '{doc_path}' was created with ID:{self.__id_counter}")
            return self.__id_counter
        else:
            DocGenerator.LOGGER.warning(f"Content for {path} is empty, ignoring it")
            return None

    def parse_folder(self, path, group_id):
        """Search in a specific folder to parse possible group files and each test file.

        Args:
            path (str): A string with the path of the folder to be parsed.
            group_id (str): A string with the id of the group where the new elements belong.
        """
        if not os.path.exists(path):
            DocGenerator.LOGGER.warning(f"Include path '{path}' doesn´t exist")
            return

        if not self.is_valid_folder(path):
            return

        (root, folders, files) = next(os.walk(path))
        for file in files:
            if self.is_group_file(file):
                new_group = self.create_group(os.path.join(root, file), group_id)
                if new_group:
                    group_id = new_group
                    break

        for file in files:
            if self.is_valid_file(file):
                self.create_test(os.path.join(root, file), group_id)

        for folder in folders:
            self.parse_folder(os.path.join(root, folder), group_id)

    def parse_test_list(self):
        """Parse the tests that the user has specified."""
        for test_name in self.conf.test_names:
            self.test_path = self.locate_test(test_name)

            if self.test_path:
                self.create_test(self.test_path, 0, test_name)
            else:
                DocGenerator.LOGGER.error(f"'{self.conf.test_name}' could not be found")

    def locate_test(self, test_name):
        """Get the test path when a test is specified by the user.

        Returns:
            str: A string with the test path.
        """
        complete_test_name = f"{test_name}.py"
        DocGenerator.LOGGER.info(f"Looking for {complete_test_name}")

        for root, dirnames, filenames in os.walk(self.conf.project_path, topdown=True):
            for filename in filenames:
                if filename == complete_test_name:
                    return os.path.join(root, complete_test_name)

        print(f"{test_name} does not exist")
        return None

    def print_test_info(self, test):
        """Print the test info to standard output.

        Args:
            test: A dict with the parsed test data
        """
        relative_path = re.sub(r'.*wazuh-qa\/', '', self.test_path)
        test['path'] = relative_path

        print(json.dumps(test, indent=4))

    def run(self):
        """Run a complete scan of each included path to parse every test and group found.

        Default mode: parse the files within the included paths.
        Single test mode: found the test required and parse it.

            For example:
            qa-docs -I ../../tests/ -> It would be running as `default mode`.

            qa-docs -I ../../tests/ -T test_cache -> It would be running as `single test mode`
            using the standard output

            qa-docs -I ../../tests/ -T test_cache -o /tmp -> It would be running as `single test mode`
            creating `/tmp/test_cache.json`
        """
        DocGenerator.LOGGER.info("Starting test documentation parsing")

        if self.conf.mode == Mode.DEFAULT:
            DocGenerator.LOGGER.debug(f"Cleaning doc folder located in {self.conf.documentation_path}")
            clean_folder(self.conf.documentation_path)
            for path in self.conf.include_paths:
                self.scan_path = path
                DocGenerator.LOGGER.debug(f"Going to parse files on '{path}'")
                self.parse_folder(path, self.__id_counter)

        elif self.conf.mode == Mode.PARSE_TESTS:
            self.parse_test_list()
