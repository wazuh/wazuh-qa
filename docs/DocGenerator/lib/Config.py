"""
brief: Wazuh DocGenerator config parser.
copyright: Copyright (C) 2015-2021, Wazuh Inc.
date: August 02, 2021
license: This program is free software; you can redistribute it
         and/or modify it under the terms of the GNU General Public
         License (version 2) as published by the FSF - Free Software Foundation.
"""

import yaml
import logging
from enum import Enum


class Config():
    """
    brief: Class that parses the configuration file and exposes the available configurations.
           It exists two modes of execution: Normal and Single test.
    """
    def __init__(self, *args):
        # If it is called using the config file
        self.mode = mode.DEFAULT
        self.project_path = "../.."
        self.documentation_path = ".."
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
            logging.error("Cannot load config file")
            raise Exception("Cannot load config file")

        self._read_function_regex()
        self._read_output_fields()
        self._read_test_cases_field()

        if len(args) == 1:
            self._read_project_path()
            self._read_documentation_path()
            self._read_include_paths()
            self._read_include_regex()
            self._read_group_files()
            self._read_ignore_paths()
            
        else:
            # It is called with a single test to parse
            self.mode = mode.SINGLE_TEST
            # Search it within the whole directory
            self.include_paths = "../../tests/"
            self.test_name = args[1]
            self.output_path = args[2]
            

    def _initialize_config(self):
        self.project_path = "../.."
        self.documentation_path = ".."
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
            with open(config_file) as fd:
                self._config_data = yaml.safe_load(fd)
        except:
            logging.error("Cannot load config file")
            raise Exception("Cannot load config file")

        self._read_project_path()
        self._read_documentation_path()
        self._read_include_paths()
        self._read_include_regex()
        self._read_group_files()
        self._read_function_regex()
        self._read_ignore_paths()
        self._read_output_fields()
        self._read_test_cases_field()

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
            logging.error("Config include paths are empty")
            raise Exception("Config include paths are empty")
        self.include_paths = self._config_data['Include paths']

    def _read_include_regex(self):
        """
        brief: Reads from the config file the regexes used to identify test files.
        """
        if not 'Include regex' in self._config_data:
            logging.error("Config include regex is empty")
            raise Exception("Config include regex is empty")
        self.include_regex = self._config_data['Include regex']

    def _read_group_files(self):
        """
        brief: Reads from the config file the file name to be identified with a group.
        """
        if not 'Group files' in self._config_data:
            logging.error("Config group files is empty")
            raise Exception("Config group files is empty")
        self.group_files = self._config_data['Group files']

    def _read_function_regex(self):
        """
        brief: Reads from the config file the regexes used to identify a test method.
        """
        if not 'Function regex' in self._config_data:
            logging.error("Config function regex is empty")
            raise Exception("Config function regex is empty")
        self.function_regex = self._config_data['Function regex']

    def _read_ignore_paths(self):
        """
        brief: Reads from the config file all the paths to be excluded from the parsing.
        """
        if 'Ignore paths' in self._config_data:
            self.ignore_paths = self._config_data['Ignore paths']

    def _read_module_fields(self):
        """
        brief: Reads from the config file the optional and mandatory fields for the test module.
        """
        if not 'Module' in self._config_data['Output fields']:
            logging.error("Config output module fields is missing")
            raise Exception("Config output module fields is missing")
        module_fields = self._config_data['Output fields']['Module']
        if not 'Mandatory' in module_fields and not 'Optional' in module_fields:
            logging.error("Config output module fields are empty")
            raise Exception("Config output module fields are empty")
        if 'Mandatory' in module_fields:
            self.module_fields.mandatory = module_fields['Mandatory']
        if 'Optional' in module_fields:
            self.module_fields.optional = module_fields['Optional']

    def _read_test_fields(self):
        """
        brief: Reads from the config file the optional and mandatory fields for the test functions.
        """
        if not 'Test' in self._config_data['Output fields']:
            logging.error("Config output test fields is missing")
            raise Exception("Config output test fields is missing")
        test_fields = self._config_data['Output fields']['Test']
        if not 'Mandatory' in test_fields and not 'Optional' in test_fields:
            logging.error("Config output test fields are empty")
            raise Exception("Config output test fields are empty")
        if 'Mandatory' in test_fields:
            self.test_fields.mandatory = test_fields['Mandatory']
        if 'Optional' in test_fields:
            self.test_fields.optional = test_fields['Optional']

    def _read_output_fields(self):
        """
        brief: Reads all the mandatory and optional fields.
        """
        if not 'Output fields' in self._config_data:
            logging.error("Config output fields is missing")
            raise Exception("Config output fields is missing")
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