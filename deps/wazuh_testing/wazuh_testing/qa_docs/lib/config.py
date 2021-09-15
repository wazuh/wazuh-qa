"""
brief: Wazuh DocGenerator config parser.
copyright: Copyright (C) 2015-2021, Wazuh Inc.
date: August 02, 2021
license: This program is free software; you can redistribute it
         and/or modify it under the terms of the GNU General Public
         License (version 2) as published by the FSF - Free Software Foundation.
"""

import yaml
from enum import Enum
import os
from wazuh_testing.qa_docs import QADOCS_LOGGER
from wazuh_testing.tools.logging import Logging
from wazuh_testing.tools.exceptions import QAValueError


class Config():
    """
    brief: Class that parses the configuration file and exposes the available configurations.
           It exists two modes of execution: Normal and Single test.
    """
    LOGGER = Logging.get_logger(QADOCS_LOGGER)

    def __init__(self, *args):
        # If it is called using the config file
        self.mode = mode.DEFAULT
        self.project_path = args[1]
        self.include_paths = []
        self.include_regex = []
        self.group_files = ""
        self.function_regex = []
        self.ignore_paths = []
        self.valid_tags = []
        self.module_fields = _fields()
        self.test_fields = _fields()
        self.test_cases_field = None

        try:
            Config.LOGGER.debug('Loading config file')
            with open(args[0]) as fd:
                self._config_data = yaml.safe_load(fd)
        except:
            raise QAValueError('Cannot load config file', Config.LOGGER.error)

        self._read_function_regex()
        self._read_output_fields()
        self._read_test_cases_field()
        self._read_include_paths()
        self._read_include_regex()
        self._read_group_files()
        self._read_ignore_paths()

        if len(args) >= 3:
            self._set_documentation_path(args[2])
        if len(args) == 4:
            # It is called with a single test to parse
            self.mode = mode.SINGLE_TEST
            self.test_name = args[3]
            self._read_test_info()
            self._read_module_info()


    def _read_test_info(self):
        """Reads from the config file the keys to be printed from module info.

        This functionality is used to print any custom field(s) you want.
        You can use it if you only need a few fields to parse when a single test is run.
        
            For example you have this in your config.yaml:

            Test info:
                - test_wazuh_min_version: wazuh_min_version
        """
        Config.LOGGER.debug('Reading test info from config file')
        if 'Test info' in self._config_data:
            self.test_info = self._config_data['Test info']
        else:
            Config.LOGGER.warning('Cannot read test info fields')
    
    def _read_module_info(self):
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

    def _set_documentation_path(self, path):
        """
        brief: Sets the path of the documentation output.
        """
        Config.LOGGER.debug('Setting the path documentation')

        if path:
            self.documentation_path = path
        else:
            Config.LOGGER.warning('You have not passed a path where the documentation data is dumped')

    def _read_include_paths(self):
        """
        brief: Reads from the config file all the paths to be included in the parsing.
        """
        Config.LOGGER.debug('Reading include paths from config file')

        # Will be replaced by --type --module and --test , so you can run what you need
        if not 'Include paths' in self._config_data:
            raise QAValueError('Config include paths are empty', Config.LOGGER.error)

        include_paths = self._config_data['Include paths']

        for path in include_paths:
            self.include_paths.append(os.path.join(self.project_path, path))

    def _read_include_regex(self):
        """
        brief: Reads from the config file the regexes used to identify test files.
        """
        Config.LOGGER.debug('Reading the regular expressions to include files from config file')

        if not 'Include regex' in self._config_data:
            raise QAValueError('Config include regex is empty', Config.LOGGER.error)

        self.include_regex = self._config_data['Include regex']

    def _read_group_files(self):
        """
        brief: Reads from the config file the file name to be identified with a group.
        """
        Config.LOGGER.debug('Reading group files from config file')

        if not 'Group files' in self._config_data:
            raise QAValueError('Config include paths are empty', Config.LOGGER.error)

        self.group_files = self._config_data['Group files']

    def _read_function_regex(self):
        """
        brief: Reads from the config file the regexes used to identify a test method.
        """
        Config.LOGGER.debug('Reading the regular expressions to include test methods from config file')

        if not 'Function regex' in self._config_data:
            raise QAValueError('Config function regex is empty', Config.LOGGER.error)

        self.function_regex = self._config_data['Function regex']

    def _read_ignore_paths(self):
        """
        brief: Reads from the config file all the paths to be excluded from the parsing.
        """
        Config.LOGGER.debug('Reading the paths to be ignored from config file')

        if 'Ignore paths' in self._config_data:
            ignore_paths = self._config_data['Ignore paths']

            for path in ignore_paths:
                self.ignore_paths.append(os.path.join(self.project_path, path))

    def _read_module_fields(self):
        """
        brief: Reads from the config file the optional and mandatory fields for the test module.
        """
        Config.LOGGER.debug('Reading mandatory and optional module fields from config file')

        if not 'Module' in self._config_data['Output fields']:
            raise QAValueError('Config output module fields is missing', Config.LOGGER.error)

        module_fields = self._config_data['Output fields']['Module']

        if not 'Mandatory' in module_fields and not 'Optional' in module_fields:
            raise QAValueError('Config output module fields are empty', Config.LOGGER.error)

        if 'Mandatory' in module_fields:
            self.module_fields.mandatory = module_fields['Mandatory']

        if 'Optional' in module_fields:
            self.module_fields.optional = module_fields['Optional']

    def _read_test_fields(self):
        """
        brief: Reads from the config file the optional and mandatory fields for the test functions.
        """
        Config.LOGGER.debug('Reading mandatory and optional test fields from config file')

        if not 'Test' in self._config_data['Output fields']:
            raise QAValueError('Config output test fields is missing', Config.LOGGER.error)
    
        test_fields = self._config_data['Output fields']['Test']

        if not 'Mandatory' in test_fields and not 'Optional' in test_fields:
            raise QAValueError('Config output test fields are empty', Config.LOGGER.error)

        if 'Mandatory' in test_fields:
            self.test_fields.mandatory = test_fields['Mandatory']

        if 'Optional' in test_fields:
            self.test_fields.optional = test_fields['Optional']

    def _read_output_fields(self):
        """
        brief: Reads all the mandatory and optional fields.
        """
        if not 'Output fields' in self._config_data:
            raise QAValueError('Config output fields is missing', Config.LOGGER.error)

        self._read_module_fields()
        self._read_test_fields()

    def _read_test_cases_field(self):
        """
        brief: Reads from the configuration file the key to identify a Test Case list.
        """
        Config.LOGGER.debug('Reading Test Case key from config file')

        if 'Test cases field' in self._config_data:
            self.test_cases_field = self._config_data['Test cases field']

class _fields:
    """
    brief: Struct for the documentation fields.
    """
    def __init__(self):
        self.mandatory = []
        self.optional = []

class mode(Enum):
    '''
    brief: Enumeration for classificate differents behaviours for DocGenerator
    '''
    DEFAULT = 1
    SINGLE_TEST = 2