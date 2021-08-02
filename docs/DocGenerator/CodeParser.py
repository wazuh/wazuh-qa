"""
brief: Wazuh DocGenerator code parser.
copyright: Copyright (C) 2015-2021, Wazuh Inc.
date: August 02, 2021
license: This program is free software; you can redistribute it
         and/or modify it under the terms of the GNU General Public
         License (version 2) as published by the FSF - Free Software Foundation.
"""

import ast
import os
import re
import json
import yaml
from Config import Config
from PytestWrap import PytestWrap
from Utils import remove_inexistent
from docstring_parser import parse
from comment_parser import comment_parser
import warnings
import logging

INTERNAL_FIELDS = ['id', 'group_id', 'name']
STOP_FIELDS = ['tests','test_cases']


class CodeParser:
    """
    brief: Class that parses the content of the test files.
    """
    def __init__(self):
        self.conf = Config()
        self.pytest = PytestWrap()
        self.function_regexes = []
        for regex in self.conf.function_regex:
            self.function_regexes.append(re.compile(regex))

    def is_documentable_function(self, function):
        """
        brief: Checks if a specific method match with the regexes to be documented.
        args: -"function (_ast.FunctionDef): Function class with all the information of the method"
        returns: "boolean: True if the method should be documentd. False otherwise"
        """
        for regex in self.function_regexes:
            if regex.match(function.name):
                return True
        return False

    def remove_ignored_fields(self, doc):
        """
        brief: Removes the fields from a parsed test file to delete the fields that are not mandatories or optionals
        args: -"doc (dict): The parsed documentation block"
        """
        allowed_fields = self.conf.module_fields.mandatory + self.conf.module_fields.optional + INTERNAL_FIELDS
        remove_inexistent(doc, allowed_fields, STOP_FIELDS)
        if 'tests' in doc:
            allowed_fields = self.conf.test_fields.mandatory + self.conf.test_fields.optional + INTERNAL_FIELDS
            for test in doc['tests']:
                remove_inexistent(test, allowed_fields, STOP_FIELDS)

    def parse_comment(self, function):
        """
        brief: Parses one self-contained documentation block.
        args: -"function (_ast.FunctionDef): Function class with all the information of the method"
        """
        docstring = ast.get_docstring(function)
        try:
            doc = yaml.safe_load(docstring)
            if hasattr(function, 'name'):
                doc['name'] = function.name

        except Exception as inst:
            if hasattr(function, 'name'):
                warnings.warn(f"Failed to parse comment of function '{function.name}'' from module {self.scan_file}. \
                              Error: {inst}", stacklevel=2)
                logging.warning(f"Failed to parse comment of function '{function.name}'' from module {self.scan_file}. \
                                Error: {inst}")
            else:
                warnings.warn(f"Failed to parse comment of module {self.scan_file}. Error: {inst}", stacklevel=2)
                logging.warning(f"Failed to parse comment of module {self.scan_file}. Error: {inst}")
            doc = None

        return doc

    def parse_test(self, code_file, id, group_id):
        """
        brief: Parses the content of a test file.
        args:
            -"code_file (string): Path of the test file to be parsed."
            -"id (integer): Id of the new test document"
            -"group_id (integer): Id of the group where the new test document belongs."
        """
        logging.debug(f"Parsing test file '{code_file}'")
        self.scan_file = code_file
        with open(code_file) as fd:
            file_content = fd.read()
        module = ast.parse(file_content)
        functions = [node for node in module.body if isinstance(node, ast.FunctionDef)]

        module_doc = self.parse_comment(module)
        if module_doc:
            module_doc['name'] = os.path.basename(code_file)
            module_doc['id'] = id
            module_doc['group_id'] = group_id

            test_cases = None
            if self.conf.test_cases_field:
                test_cases = self.pytest.collect_test_cases(code_file)

            functions_doc = []
            for function in functions:
                if self.is_documentable_function(function):
                    function_doc = self.parse_comment(function)
                    if function_doc:
                        if test_cases and not self.conf.test_cases_field in function_doc \
                           and test_cases[function.name]:
                            function_doc[self.conf.test_cases_field] = test_cases[function.name]
                        functions_doc.append(function_doc)

            if not functions_doc:
                warnings.warn(f"Module '{module_doc['name']}' doesn´t contain any test function", stacklevel=2)
                logging.warning(f"Module '{module_doc['name']}' doesn´t contain any test function")
            else:
                module_doc['tests'] = functions_doc

            self.remove_ignored_fields(module_doc)

        return module_doc

    def parse_group(self, group_file, id, group_id):
        """
        brief: Parses the content of a group file.
        args:
            -"group_file (string): Path of the group file to be parsed."
            -"id (integer): Id of the new group document"
            -"group_id (integer): Id of the group where the new group document belongs."
        """
        logging.debug(f"Parsing group file '{group_file}'")
        with open(group_file) as fd:
            file_content = fd.read()
        group_doc = {}
        group_doc['name'] = os.path.basename(os.path.dirname(group_file))
        group_doc['id'] = id
        group_doc['group_id'] = group_id
        group_doc['description'] = file_content

        return group_doc
