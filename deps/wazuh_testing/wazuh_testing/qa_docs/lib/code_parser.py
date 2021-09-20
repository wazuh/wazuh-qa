# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import ast
import os
import re
import yaml

from wazuh_testing.qa_docs.lib.pytest_wrap import PytestWrap
from wazuh_testing.qa_docs.lib.utils import remove_inexistent
from wazuh_testing.qa_docs import QADOCS_LOGGER
from wazuh_testing.tools.logging import Logging

INTERNAL_FIELDS = ['id', 'group_id', 'name']
STOP_FIELDS = ['tests', 'test_cases']


class CodeParser:
    """Class that parses the content of the test files.

    Attributes:
        conf: A `Config` instance with the config file data.
        pytest: A `PytestWrap` instance to wrap the pytest execution.
        function_regexes: A list of strings(regular expressions) used to find test functions..
    """
    LOGGER = Logging.get_logger(QADOCS_LOGGER)

    def __init__(self, config):
        self.conf = config
        self.pytest = PytestWrap()
        self.function_regexes = []
        for regex in self.conf.function_regex:
            self.function_regexes.append(re.compile(regex))

    def is_documentable_function(self, function):
        """Checks if a specific method matches with the regexes to be documented.

        Args:
            function: Function class(_ast.FunctionDef) with all the information of the method.
        Returns:
            A boolean with True if the method should be documented. False otherwise
        """
        for regex in self.function_regexes:
            if regex.match(function.name):
                return True
        return False

    def remove_ignored_fields(self, doc):
        """Removes the fields from a parsed test file to delete the fields that are not mandatory or optional.

        Args:
            doc: A dict that contains the parsed documentation block"
        """
        allowed_fields = self.conf.module_fields.mandatory + self.conf.module_fields.optional + INTERNAL_FIELDS
        remove_inexistent(doc, allowed_fields, STOP_FIELDS)

        if 'tests' in doc:
            allowed_fields = self.conf.test_fields.mandatory + self.conf.test_fields.optional + INTERNAL_FIELDS

            for test in doc['tests']:
                remove_inexistent(test, allowed_fields, STOP_FIELDS)

    def parse_comment(self, function):
        """Parses one self-contained documentation block.

        Args:
            function: Function class(_ast.FunctionDef) with all the information of the method"
        """
        docstring = ast.get_docstring(function)

        try:
            doc = yaml.safe_load(docstring)

            if hasattr(function, 'name'):
                doc['name'] = function.name

        except Exception as inst:
            if hasattr(function, 'name'):
                CodeParser.LOGGER.warning(f"Failed to parse test documentation in {function.name} "
                                          "from module {self.scan_file}. Error: {inst}")
            else:
                CodeParser.LOGGER.warning(f"Failed to parse module documentation in  {self.scan_file}. Error: {inst}")

            doc = None

        return doc

    def parse_test(self, code_file, id, group_id):
        """Parses the content of a test file.

        Args:
            code_file: A string with the path of the test file to be parsed.
            id: An integer with the ID of the new test document.
            group_id: An integer with the ID of the group where the new test document belongs.
        """
        CodeParser.LOGGER.debug(f"Parsing test file '{code_file}'")
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
                        if test_cases and not (self.conf.test_cases_field in function_doc) \
                           and test_cases[function.name]:
                            function_doc[self.conf.test_cases_field] = test_cases[function.name]

                        functions_doc.append(function_doc)

            if not functions_doc:
                CodeParser.LOGGER.warning(f"Module '{module_doc['name']}' doesn´t contain any test function")
            else:
                module_doc['tests'] = functions_doc

            self.remove_ignored_fields(module_doc)

        return module_doc

    def parse_group(self, group_file, id, group_id):
        """Parses the content of a group file.

        Args:
            group_file: A string with the path of the group file to be parsed.
            id: An integer with the ID of the new test document.
            group_id: An integer with the ID of the group where the new test document belongs.
        """
        MD_HEADER = "# "
        CodeParser.LOGGER.debug(f"Parsing group file '{group_file}'")
        with open(group_file) as fd:
            file_header = fd.readline()
            file_content = fd.read()

        if not file_header.startswith(MD_HEADER):
            CodeParser.LOGGER.warning(f"Group file '{group_file}' doesn´t contain a valid header")
            return None

        group_doc = {}
        group_doc['name'] = file_header.replace(MD_HEADER, "").replace("\n", "")
        group_doc['id'] = id
        group_doc['group_id'] = group_id
        group_doc['description'] = file_content

        return group_doc
