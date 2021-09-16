# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import yaml
from enum import Enum
import os
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
        mode: An enumeration that stores the `doc_generator` mode when it is running.
        project_path: A string that specifies the path where the tests to parse are located.
        include_paths: A list of strings that contains the directories to parse.
        include_regex: A list of strings(regular expressions) used to find test files.
        group_files: A string that specifies the group definition file.
        function_regex: A list of strings(regular expressions) used to find test functions.
        ignore_paths: A string that specifies which paths will be ignored.
        module_fields: A struct that contains the module documentation data.
        test_fields: A struct that contains the test documentation data.
        test_cases_field: A string that contains the test cases key.
        LOGGER: A custom qa-docs logger.
    """
    LOGGER = Logging.get_logger(QADOCS_LOGGER)

    def __init__(self, config_path, test_dir, output_path='', test_name=None):
        """Constructor that loads the data from the config file.

        Also, if a test name is passed, it will be run in single test mode.
        And if an output path is not received, when is running in single test mode, it will be printed using the
        standard output. But if an output path is passed, there will be generated a JSON file with the same data that
        would be printed in `single test` mode.

        The default output path for `default mode` is `qa_docs_installation/output`, it cannot be changed. Even when
        you pass an output path, it has no effect in `default mode`.

        Args:
            config_path: A string that contains the config file path.
            test_dir: A string that contains the path of the tests.
            output_path: A string that contains the doc output path.
            test_name: A string that represents a test name.
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

        self.__read_config_file(config_path)
        self.__read_function_regex()
        self.__read_output_fields()
        self.__read_test_cases_field()
        self.__read_include_paths()
        self.__read_include_regex()
        self.__read_group_files()
        self.__read_ignore_paths()
        self.__set_documentation_path(output_path)

        if test_name:
            # When a name is passed, it is using just a single test.
            self.mode = Mode.SINGLE_TEST
            self.test_name = test_name
            self.__read_test_info()
            self.__read_module_info()


    def __read_config_file(self, file):
        """Reads configuration file.
        
        Raises:
            QAValuerError: Cannot load config file.
        """
        try:
            Config.LOGGER.debug('Loading config file')
            with open(file) as config_file:
                self._config_data = yaml.safe_load(config_file)
        except:
            raise QAValueError('Cannot load config file', Config.LOGGER.error)

    def __read_test_info(self):
        """Reads from the config file the keys to be printed from module info.

        This functionality is used to print any custom field(s) you want.
        You can use it if you only need a few fields to parse when a single test is run.
        
            For example, you have this in your config.yaml:

            Test info:
                - test_wazuh_min_version: wazuh_min_version
        """
        Config.LOGGER.debug('Reading test info from the config file')
        if 'Test info' in self._config_data:
            self.test_info = self._config_data['Test info']
        else:
            Config.LOGGER.warning('Cannot read test info fields')
    
    def __read_module_info(self):
        """Reads from the config file the fields to be printed from test info.

        This functionality is used to print any custom field(s) you want.
        You can use it if you only need a few fields to parse when a single test is run.
        
            For example you have this in your config.yaml:

            Module info:
                - test_system: os_platform
                - test_vendor: os_vendor
                - test_version: os_version
                - test_target: component
        """
        Config.LOGGER.debug('Reading module info from config file')

        if 'Module info' in self._config_data:
            self.module_info = self._config_data['Module info']
        else:
            Config.LOGGER.warning('Cannot read module info fields')

    def __set_documentation_path(self, path):
        """Sets the path of the documentation output."""
        Config.LOGGER.debug('Setting the path documentation')
        self.documentation_path = path

    def __read_include_paths(self):
        """Reads from the config file all the paths to be included in the parsing process.

        Raises:
            QAValueError: The include paths field is empty in the config file
        """
        Config.LOGGER.debug('Reading include paths from config file')

        # Will be replaced by --type --module and --test , so you can run what you need
        if not 'Include paths' in self._config_data:
            raise QAValueError('The include paths field is empty in the config file', Config.LOGGER.error)

        include_paths = self._config_data['Include paths']

        for path in include_paths:
            self.include_paths.append(os.path.join(self.project_path, path))

    def __read_include_regex(self):
        """Reads from the config file the regexes used to identify test files.

        Raises:
            QAValueError: The include regex field is empty in the config file
        """
        Config.LOGGER.debug('Reading the regular expressions from the config file to include test files')

        if not 'Include regex' in self._config_data:
            raise QAValueError('The include regex field is empty in the config file', Config.LOGGER.error)

        self.include_regex = self._config_data['Include regex']

    def __read_group_files(self):
        """Reads from the config file the file name to be identified in a group.

        Raises:
            QAValueError: The group files field is empty in config file
        """
        Config.LOGGER.debug('Reading group files from the config file')

        if not 'Group files' in self._config_data:
            raise QAValueError('The group files field is empty in config file', Config.LOGGER.error)

        self.group_files = self._config_data['Group files']

    def __read_function_regex(self):
        """Reads from the config file the regexes used to identify a test method.

        Raises:
            QAValueError: The function regex field is empty in the config file
        """
        Config.LOGGER.debug('Reading the regular expressions to include test methods from the config file')

        if not 'Function regex' in self._config_data:
            raise QAValueError('The function regex field is empty in the config file', Config.LOGGER.error)

        self.function_regex = self._config_data['Function regex']

    def __read_ignore_paths(self):
        """Reads from the config file all the paths to be excluded from the parsing."""

        if 'Ignore paths' in self._config_data:
            ignore_paths = self._config_data['Ignore paths']

            for path in ignore_paths:
                self.ignore_paths.append(os.path.join(self.project_path, path))

    def __read_module_fields(self):
        """Reads from the config file the optional and mandatory fields for the test module.
        
        If the module block fields are not defined in the config file, an error will be raised.

        Raises:
            QAValueError: Module fields are missing in the config file
            QAValueError: Mandatory module fields are missing in the config file
        """
        Config.LOGGER.debug('Reading mandatory and optional module fields from the config file')

        if not 'Module' in self._config_data['Output fields']:
            raise QAValueError('Module fields are missing in the config file', Config.LOGGER.error)

        module_fields = self._config_data['Output fields']['Module']

        if not 'Mandatory' in module_fields and not 'Optional' in module_fields:
            raise QAValueError('Mandatory module fields are missing in the config file', Config.LOGGER.error)

        if 'Mandatory' in module_fields:
            self.module_fields.mandatory = module_fields['Mandatory']

        if 'Optional' in module_fields:
            self.module_fields.optional = module_fields['Optional']

    def __read_test_fields(self):
        """Reads from the config file the optional and mandatory fields for the test functions.

        If the test block fields are not defined in the config file, an error will be raised.

        Raises:
           QAValueError: Test fields are missing in the config file
           QAValueError: Mandatory module fields are missing in the config file
        """
        Config.LOGGER.debug('Reading mandatory and optional test fields from the config file')

        if not 'Test' in self._config_data['Output fields']:
            raise QAValueError('Test fields are missing in the config file', Config.LOGGER.error)
    
        test_fields = self._config_data['Output fields']['Test']

        if not 'Mandatory' in test_fields and not 'Optional' in test_fields:
            raise QAValueError('Mandatory module fields are missing in the config file', Config.LOGGER.error)

        if 'Mandatory' in test_fields:
            self.test_fields.mandatory = test_fields['Mandatory']

        if 'Optional' in test_fields:
            self.test_fields.optional = test_fields['Optional']

    def __read_output_fields(self):
        """Reads all the mandatory and optional fields from config file.
        
        Raises:
            QAValueError: Documentation schema not defined in the config file
        """
        if not 'Output fields' in self._config_data:
            raise QAValueError('Documentation schema not defined in the config file', Config.LOGGER.error)

        self.__read_module_fields()
        self.__read_test_fields()

    def __read_test_cases_field(self):
        """Reads from the configuration file the key to identify a Test Case list."""
        Config.LOGGER.debug('Reading Test Case key from the config file')

        if 'Test cases field' in self._config_data:
            self.test_cases_field = self._config_data['Test cases field']

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
            DEFAULT: `default mode` parses all tests within tests directory
            SINGLE_TEST: `single test mode` only uses a single test represented by its name

            For example, if you want to declare that it is running thru all tests directory, you must specify it by:

            mode = Mode.DEFAULT

    Args:
        Enum: Base class for creating enumerated constants.
    """
    DEFAULT = 1
    SINGLE_TEST = 2