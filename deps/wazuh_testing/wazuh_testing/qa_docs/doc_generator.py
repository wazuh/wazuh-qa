# Copyright (C) 2015-2022, Wazuh Inc.
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
from wazuh_testing.qa_docs.lib.utils import get_file_path_recursively


class DocGenerator:
    """Main class of DocGenerator tool.

    It is in charge of walk every module file, and every group file to dump the parsed documentation.
    Every folder is checked so they are ignored when the path matches. Then, every module from folders not ignored
    that matches a include regex, is parsed.

    The included paths are generated using the types and modules from the wazuh-qa framework.

    Attributes:
        conf (Config): A `Config` instance with the loaded configuration.
        parser (CodeParser): A `CodeParser` instance with parsing utilities.
        __id_counter (int): An integer that counts the module/group ID when it is created.
        ignore_regex (list): A list with compiled paths to be ignored.
        include_regex (list): A list with regular expressions used to parse a file or not.
        file_format (str): Generated documentation format.
    """
    LOGGER = Logging.get_logger(QADOCS_LOGGER)

    def __init__(self, config, file_format='json'):
        """Class constructor

        Initialize every attribute.

        Args:
            config (Config): A `Config` instance with the loaded configuration.
            file_format (str): Generated documentation format.
        """
        self.conf = config
        self.parser = CodeParser(self.conf)
        self.__id_counter = 0
        self.ignore_regex = []
        for ignore_regex in self.conf.ignore_paths:
            self.ignore_regex.append(re.compile(ignore_regex.replace('\\', '/')))
        self.include_regex = []
        for include_regex in self.conf.include_regex:
            self.include_regex.append(re.compile(include_regex.replace('\\', '/')))
        self.file_format = file_format

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

    def get_module_doc_path(self, path):
        """Get the name of the module file in the documentation output based on the original file name.

        Args:
            path (str): A string that contains the original file name.

        Returns:
            doc_path (str): A string with the name of the documentation module file.
        """
        base_path = os.path.join(self.conf.documentation_path, os.path.basename(self.scan_path))
        relative_path = path.replace(self.scan_path, "")
        doc_path = os.path.splitext(base_path + relative_path)[0]

        return doc_path

    def dump_output(self, content, doc_path):
        """Create a JSON and a YAML file with the parsed content of a test module.

        Also, create the containing folder if it does not exist.

        Args:
            content (dict): A dict that contains the parsed content of a module file.
            doc_path (str): A string with the path where the information should be dumped.

        Raises:
            QAValueError: Cannot write in {doc_path}.json
            QAValueError: Cannot write in {doc_path}.yaml
        """
        if not os.path.exists(os.path.dirname(doc_path)):
            DocGenerator.LOGGER.debug('Creating documentation folder')
            os.makedirs(os.path.dirname(doc_path))

        if self.file_format == 'json':
            DocGenerator.LOGGER.debug(f"Writing {doc_path}.json")

            try:
                with open(f"{doc_path}.json", 'w+') as out_file:
                    out_file.write(f"{json.dumps(content, indent=4)}\n")
            except IOError:
                raise QAValueError(f"Cannot write in {doc_path}.json", DocGenerator.LOGGER.error)

        if self.file_format == 'yaml':
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
            None if the module does not have documentation.
        """
        self.__id_counter = self.__id_counter + 1
        group = self.parser.parse_group(path, self.__id_counter, group_id)

        if group:
            doc_path = self.get_group_doc_path(group)
            self.dump_output(group, doc_path)
            DocGenerator.LOGGER.debug(f"New group file '{doc_path}' was created with ID:{self.__id_counter}")
            return self.__id_counter
        else:
            DocGenerator.LOGGER.error(f"Content for {path} is empty, ignoring it")
            raise QAValueError(f"Content for {path} is empty, ignoring it", DocGenerator.LOGGER.error)

    def create_module(self, path, group_id, module_name=None):
        """Parse the content of a module file and dumps the content into a file.

        Modes:
            Single module:
                When a single module is going to be parsed, if it has not an output directory, the content is printed.
                If it has an output dir, the content is dumped into that dir.

            Default:
                The content is dumped into the corresponding directory.

        Args:
            path (str): A string with the path of the module file to be parsed.
            group_id (str): A string with the id of the group where the new module belongs.
            module_name (str): A string with the name of the module that is going to be parsed.

        Returns:
            __id.counter (int): An integer with the ID of the new generated module document.
            None if the module does not have documentation.
        """
        self.__id_counter = self.__id_counter + 1
        tests = self.parser.parse_module(path, self.__id_counter, group_id)

        if tests:
            doc_path = self.get_module_doc_path(path)

            self.dump_output(tests, doc_path)
            DocGenerator.LOGGER.debug(f"New documentation file '{doc_path}' was created with ID:{self.__id_counter}")
            return self.__id_counter
        else:
            DocGenerator.LOGGER.error(f"Content for {path} is empty, ignoring it")
            raise QAValueError(f"Content for {path} is empty, ignoring it", DocGenerator.LOGGER.error)

    def parse_folder(self, path, group_id):
        """Search in a specific folder to parse possible group files and each module file.

        Args:
            path (str): A string with the path of the folder to be parsed.
            group_id (str): A string with the id of the group where the new elements belong.
        """
        if not os.path.exists(path):
            DocGenerator.LOGGER.error(f"Include path '{path}' doesn´t exist")
            raise QAValueError(f"Include path '{path}' doesn´t exist", DocGenerator.LOGGER.error)

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
                self.create_module(os.path.join(root, file), group_id)

        for folder in folders:
            self.parse_folder(os.path.join(root, folder), group_id)

    def parse_module_list(self):
        """Parse the modules that the user has specified."""
        for module_index in range(len(self.conf.include_paths)):
            if self.is_valid_file(f"{self.conf.test_modules[module_index]}.py"):
                self.scan_path = self.conf.include_paths[module_index]
                self.create_module(self.conf.include_paths[module_index], 0)
            else:
                DocGenerator.LOGGER.error(f"'{self.conf.test_modules[module_index]}' not a valid module file.")
                raise QAValueError(f"'{self.conf.test_modules[module_index]}'  not a valid module file.",
                                   DocGenerator.LOGGER.error)

    def locate_module(self, module_name):
        """Get the module path when a module is specified by the user.

        Returns:
            str: A string with the module path.
        """
        complete_module_name = f"{module_name}.py"
        DocGenerator.LOGGER.info(f"Looking for {complete_module_name}")

        if self.conf.test_types:
            path_where_looks_for = os.path.join(self.conf.project_path, self.conf.test_types[0])
            if self.conf.test_components:
                path_where_looks_for = os.path.join(path_where_looks_for, self.conf.test_components[0])
                if self.conf.test_suites:
                    path_where_looks_for = os.path.join(path_where_looks_for, self.conf.test_suites[0])

        return get_file_path_recursively(complete_module_name, path_where_looks_for)

    def check_module_exists(self, path):
        """Check that a module exists within the modules path input.

        Args:
            path (str): A string with the modules path.
        """
        for module in self.conf.test_modules:
            if self.locate_module(module):
                print(f'{module} exists in {path}')
            else:
                print(f'{module} does not exist in {path}')

    def check_documentation(self):
        for module in self.conf.test_modules:
            module_path = self.locate_module(module)
            try:
                test = self.parser.parse_module(module_path, self.__id_counter, 0)
            except Exception as qaerror:
                test = None
                print(f"{module} is not documented using qa-docs current schema")

            if test:
                print(f"{module} is documented using qa-docs current schema")

    def print_module_info(self, module):
        """Print the module info to standard output.

        Args:
            module: A dict with the parsed module data
        """
        relative_path = re.sub(r'.*wazuh-qa\/', '', self.module_path)
        module['path'] = relative_path

        print(json.dumps(module, indent=4))

    def run(self):
        """Run a complete scan of each included path to parse every module and group found.

        Default mode: parse the files within the included paths.
        Single module mode: found the module required and parse it.

            For example:
            qa-docs -I ../../tests/ -> It would be running as `default mode`.

            qa-docs -I ../../tests/ -m test_cache -> It would be running as `single module mode`
            using the standard output

            qa-docs -I ../../tests/ -m test_cache -o /tmp -> It would be running as `single module mode`
            creating `/tmp/test_cache.json`
        """
        if not self.conf.check_doc:
            DocGenerator.LOGGER.debug(f"Cleaning doc folder located in {self.conf.documentation_path}")
            clean_folder(self.conf.documentation_path)

        if self.conf.mode == Mode.DEFAULT:
            for path in self.conf.include_paths:
                self.scan_path = path
                DocGenerator.LOGGER.debug(f"Going to parse files on '{path}'")
                self.parse_folder(path, self.__id_counter)

        elif self.conf.mode == Mode.PARSE_MODULES:
            self.parse_module_list()

        if not self.conf.check_doc:
            DocGenerator.LOGGER.info(f"Run completed, documentation location: {self.conf.documentation_path}")
