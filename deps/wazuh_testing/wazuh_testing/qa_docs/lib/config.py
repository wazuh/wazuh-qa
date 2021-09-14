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
            with open(args[0]) as fd:
                self._config_data = yaml.safe_load(fd)
        except:
            Config.LOGGER.error('Cannot load config file')
            raise QAValueError('Cannot load config file', Config.LOGGER.error)

        self._read_function_regex()
        self._read_output_fields()
        self._read_test_cases_field()
        self._read_documentation_path()
        self._read_include_paths()
        self._read_include_regex()
        self._read_group_files()
        self._read_ignore_paths()

        if len(args) >= 3:
            self.documentation_path = args[2]
        if len(args) == 4:
            # It is called with a single test to parse
            self.mode = mode.SINGLE_TEST
            self.test_name = args[3]
            self._read_test_info()
            self._read_module_info()


    def _read_test_info(self):
        '''
        brief: Reads from the config file the keys to be printed from test info
        '''
        if 'Test info' in self._config_data:
            self.test_info = self._config_data['Test info']
    
    def _read_module_info(self):
        '''
        brief: Reads from the config file the keys to be printed from module info
        '''
        if 'Module info' in self._config_data:
            self.module_info = self._config_data['Module info']

    def _read_project_path(self):
        """
        brief: Reads from the config file the path of the project.
        """
        if 'Project path' in self._config_data:
            self.project_path = self._config_data['Project path']

    def _read_documentation_path(self):
        """
        brief: Reads from the config file the path of the documentation output.
        """
        if 'Output path' in self._config_data:
            self.documentation_path = self._config_data['Output path']

    def _read_include_paths(self):
        """
        brief: Reads from the config file all the paths to be included in the parsing.
        """
        if not 'Include paths' in self._config_data:
            Config.LOGGER.error('Config include paths are empty')
            raise QAValueError('Config include paths are empty', Config.LOGGER.error)
        include_paths = self._config_data['Include paths']
        for path in include_paths:
            self.include_paths.append(os.path.join(self.project_path, path))

    def _read_include_regex(self):
        """
        brief: Reads from the config file the regexes used to identify test files.
        """
        if not 'Include regex' in self._config_data:
            Config.LOGGER.error('Config include regex is empty')
            raise QAValueError('Config include regex is empty', Config.LOGGER.error)
        self.include_regex = self._config_data['Include regex']

    def _read_group_files(self):
        """
        brief: Reads from the config file the file name to be identified with a group.
        """
        if not 'Group files' in self._config_data:
            Config.LOGGER.error("Config group files is empty")
            raise QAValueError('Config include paths are empty', Config.LOGGER.error)
        self.group_files = self._config_data['Group files']

    def _read_function_regex(self):
        """
        brief: Reads from the config file the regexes used to identify a test method.
        """
        if not 'Function regex' in self._config_data:
            Config.LOGGER.error('Config function regex is empty')
            raise QAValueError('Config function regex is empty', Config.LOGGER.error)
        self.function_regex = self._config_data['Function regex']

    def _read_ignore_paths(self):
        """
        brief: Reads from the config file all the paths to be excluded from the parsing.
        """
        if 'Ignore paths' in self._config_data:
            ignore_paths = self._config_data['Ignore paths']
            for path in ignore_paths:
                self.ignore_paths.append(os.path.join(self.project_path, path))

    def _read_module_fields(self):
        """
        brief: Reads from the config file the optional and mandatory fields for the test module.
        """
        if not 'Module' in self._config_data['Output fields']:
            Config.LOGGER.error('Config output module fields is missing')
            raise QAValueError('Config output module fields is missing', Config.LOGGER.error)
        module_fields = self._config_data['Output fields']['Module']
        if not 'Mandatory' in module_fields and not 'Optional' in module_fields:
            Config.LOGGER.error('Config output module fields are empty')
            raise QAValueError('Config output module fields are empty', Config.LOGGER.error)
        if 'Mandatory' in module_fields:
            self.module_fields.mandatory = module_fields['Mandatory']
        if 'Optional' in module_fields:
            self.module_fields.optional = module_fields['Optional']

    def _read_test_fields(self):
        """
        brief: Reads from the config file the optional and mandatory fields for the test functions.
        """
        if not 'Test' in self._config_data['Output fields']:
            Config.LOGGER.error('Config output test fields is missing')
            raise QAValueError('Config output test fields is missing', Config.LOGGER.error)
        test_fields = self._config_data['Output fields']['Test']
        if not 'Mandatory' in test_fields and not 'Optional' in test_fields:
            Config.LOGGER.error('Config output test fields are empty')
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
            Config.LOGGER.error('Config output fields is missing')
            raise QAValueError('Config output fields is missing', Config.LOGGER.error)
        self._read_module_fields()
        self._read_test_fields()

    def _read_test_cases_field(self):
        """
        brief: Reads from the configuration file the key to identify a Test Case list.
        """
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