# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import yaml
from enum import Enum
import os
import re

from wazuh_testing.qa_docs import QADOCS_LOGGER
from wazuh_testing.tools.logging import Logging
from wazuh_testing.tools.exceptions import QAValueError


class Config():
    """Class that parses the configuration file and exposes the available configurations.

    Exist two modes of execution: `default mode` and `single test mode`.
    The following attributes may change because the config file will be deprecated soon. It will be renamed to
    `schema.yaml` and it will specify the schema fields and pre-defined values that you can check here:
    https://github.com/wazuh/wazuh-qa/wiki/Documenting-tests-using-the-qadocs-schema#schema-blocks

    Attributes:
        mode (Mode): An enumeration that stores the `doc_generator` mode when it is running.
        project_path (str): A string that specifies the path where the tests to parse are located.
        include_paths (str): A list of strings that contains the directories to parse.
        include_regex (str): A list of strings(regular expressions) used to find test files.
        group_files (str): A string that specifies the group definition file.
        function_regex (list): A list of regular expressions used to find test functions.
        ignore_paths (str): A string that specifies which paths will be ignored.
        module_fields (_fields): A struct that contains the module documentation data.
        test_fields (_fields): A struct that contains the test documentation data.
        test_cases_field (_fields): A string that contains the test_cases key.
        test_types (list): A list with the types to be parsed.
        test_modules (list): A list with the modules to be parsed.
        test_names (list): A list with the tests to be parsed.
        LOGGER (_fields): A custom qa-docs logger.
    """
    LOGGER = Logging.get_logger(QADOCS_LOGGER)

    def __init__(self, config_path, test_dir, output_path='', test_types=None, test_modules=None, test_names=None):
        """Constructor that loads the data from the config file.

        Also, if a test name is passed, it will be run in single test mode.
        And if an output path is not received, when is running in single test mode, it will be printed using the
        standard output. But if an output path is passed, there will be generated a JSON file with the same data that
        would be printed in `single test` mode.

        The default output path for `default mode` is `qa_docs_installation/output`, it cannot be changed. Even when
        you pass an output path, it has no effect in `default mode`.

        Args:
            config_path (str): A string that contains the config file path.
            test_dir (str): A string that contains the path of the tests.
            output_path (str): A string that contains the doc output path.
            test_types (list): A list that contains the tests type(s) to be parsed.
            test_types (list): A list that contains the test type(s) that the user specifies.
            test_modules (list): A list that contains the test module(s) that the user specifies.
            test_names (list): A list that contains the test name(s) that the user specifies.
        """
        self.mode = Mode.DEFAULT
        self.project_path = test_dir
        self.include_paths = []
        self.include_regex = []
        self.group_files = ""
        self.function_regex = []
        self.ignore_paths = []
        self.module_fields = _fields()
        self.test_fields = _fields()
        self.test_cases_field = None
        self.test_types = []
        self.test_modules = []

        self.__read_config_file(config_path)
        self.__read_function_regex()
        self.__read_output_fields()
        self.__read_test_cases_field()
        self.__read_include_regex()
        self.__read_group_files()
        self.__read_ignore_paths()
        self.__set_documentation_path(output_path)

        if test_names is not None:
            # When a name is passed, it is using just a single test.
            self.mode = Mode.PARSE_TESTS
            self.test_names = test_names

        # Add all the types within the tests directory by default
        if test_types is None:
            self.__get_test_types()
        # Add the user types to include_paths
        else:
            self.test_types = test_types

            if test_modules:
                self.test_modules = test_modules

        # Get the tests types to parse
        self.__get_include_paths()

    def __read_config_file(self, file):
        """Read configuration file.

        Raises:
            QAValuerError (IOError): Cannot load config file.
        """
        try:
            Config.LOGGER.debug('Loading config file')
            with open(file) as config_file:
                self._config_data = yaml.safe_load(config_file)
        except IOError:
            raise QAValueError('Cannot load config file', Config.LOGGER.error)

    def __set_documentation_path(self, path):
        """Set the path of the documentation output."""
        Config.LOGGER.debug('Setting the path documentation')
        self.documentation_path = path

    def __get_test_types(self):
        """Get all the test types within wazuh-qa framework."""
        for name in os.listdir(self.project_path):
            if os.path.isdir(os.path.join(self.project_path, name)):
                self.test_types.append(name)

    def __get_include_paths(self):
        """Get all the modules to include within all the specified types.
        
        The paths to be included are generated using this info.
        """
        dir_regex = re.compile("test_.")
        self.include_paths = []

        for type in self.test_types:
            subset_tests = os.path.join(self.project_path, type)

            if self.test_modules:
                for name in self.test_modules:
                    self.include_paths.append(os.path.join(subset_tests, name))
            else:
                for name in os.listdir(subset_tests):
                    if os.path.isdir(os.path.join(subset_tests, name)) and dir_regex.match(name):
                        self.include_paths.append(os.path.join(subset_tests, name))

    def __read_include_regex(self):
        """Read from the config file the regexes used to identify test files.

        Raises:
            QAValueError: The include regex field is empty in the config file
        """
        Config.LOGGER.debug('Reading the regular expressions from the config file to include test files')

        if 'include_regex' not in self._config_data:
            raise QAValueError('The include regex field is empty in the config file', Config.LOGGER.error)

        self.include_regex = self._config_data['include_regex']

    def __read_group_files(self):
        """Read from the config file the file name to be identified in a group.

        Raises:
            QAValueError: The group files field is empty in config file
        """
        Config.LOGGER.debug('Reading group files from the config file')

        if 'group_files' not in self._config_data:
            raise QAValueError('The group files field is empty in config file', Config.LOGGER.error)

        self.group_files = self._config_data['group_files']

    def __read_function_regex(self):
        """Read from the config file the regexes used to identify a test method.

        Raises:
            QAValueError: The function regex field is empty in the config file
        """
        Config.LOGGER.debug('Reading the regular expressions to include test methods from the config file')

        if 'function_regex' not in self._config_data:
            raise QAValueError('The function regex field is empty in the config file', Config.LOGGER.error)

        self.function_regex = self._config_data['function_regex']

    def __read_ignore_paths(self):
        """Read from the config file all the paths to be excluded from the parsing."""

        if 'ignore_paths' in self._config_data:
            ignore_paths = self._config_data['ignore_paths']

            for path in ignore_paths:
                self.ignore_paths.append(os.path.join(self.project_path, path))

    def __read_module_fields(self):
        """Read from the config file the optional and mandatory fields for the test module.

        If the module block fields are not defined in the config file, an error will be raised.

        Raises:
            QAValueError: module fields are missing in the config file
            QAValueError: mandatory module fields are missing in the config file
        """
        Config.LOGGER.debug('Reading mandatory and optional module fields from the config file')

        if 'module' not in self._config_data['output_fields']:
            raise QAValueError('module fields are missing in the config file', Config.LOGGER.error)

        module_fields = self._config_data['output_fields']['module']

        if 'mandatory' not in module_fields and 'optional' not in module_fields:
            raise QAValueError('mandatory module fields are missing in the config file', Config.LOGGER.error)

        if 'mandatory' in module_fields:
            self.module_fields.mandatory = module_fields['mandatory']

        if 'optional' in module_fields:
            self.module_fields.optional = module_fields['optional']

    def __read_test_fields(self):
        """Read from the config file the optional and mandatory fields for the test functions.

        If the test block fields are not defined in the config file, an error will be raised.

        Raises:
           QAValueError: test_fields are missing in the config file
           QAValueError: mandatory module fields are missing in the config file
        """
        Config.LOGGER.debug('Reading mandatory and optional test fields from the config file')

        if 'test' not in self._config_data['output_fields']:
            raise QAValueError('test_fields are missing in the config file', Config.LOGGER.error)

        test_fields = self._config_data['output_fields']['test']

        if 'mandatory' not in test_fields and 'optional' not in test_fields:
            raise QAValueError('mandatory module fields are missing in the config file', Config.LOGGER.error)

        if 'mandatory' in test_fields:
            self.test_fields.mandatory = test_fields['mandatory']

        if 'optional' in test_fields:
            self.test_fields.optional = test_fields['optional']

    def __read_output_fields(self):
        """Read all the mandatory and optional fields from config file.

        Raises:
            QAValueError: Documentation schema not defined in the config file
        """
        if 'output_fields' not in self._config_data:
            raise QAValueError('Documentation schema not defined in the config file', Config.LOGGER.error)

        self.__read_module_fields()
        self.__read_test_fields()

    def __read_test_cases_field(self):
        """Read from the configuration file the key to identify a Test Case list."""
        Config.LOGGER.debug('Reading Test Case key from the config file')

        if 'test_cases_field' in self._config_data:
            self.test_cases_field = self._config_data['test_cases_field']


class _fields:
    """Struct for the documentation fields.

    Attributes:
        mandatory: A list of strings that contains the mandatory block fields
        optional: A list of strings that contains the optional block fields
    """
    def __init__(self):
        self.mandatory = []
        self.optional = []


class Mode(Enum):
    """Enumeration for behaviour classification

    The current modes that `doc_generator` has are these:

        Modes:
            DEFAULT: `default mode` parses all tests within tests directory.
            PARSE_TESTS: `single tests mode` parses a list of tests.
            PARSE_TYPES

            For example, if you want to declare that it is running thru all tests directory, you must specify it by:

            mode = Mode.DEFAULT

    Args:
        Enum (Class): Base class for creating enumerated constants.
    """
    DEFAULT = 1
    PARSE_TESTS = 2
