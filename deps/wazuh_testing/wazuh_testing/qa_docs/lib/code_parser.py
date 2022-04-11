# Copyright (C) 2015-2022, Wazuh Inc.
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
from wazuh_testing.tools.exceptions import QAValueError

INTERNAL_FIELDS = ['id', 'group_id', 'name']
STOP_FIELDS = ['tests', 'test_cases']


class CodeParser:
    """Class that parses the content of the module files.

    Attributes:
        conf (Config): A `Config` instance with the loaded configuration.
        pytest (PytestWrap): A `PytestWrap` instance to wrap the pytest execution.
        function_regexes (list): A list of regular expressions used to find test functions.
    """
    LOGGER = Logging.get_logger(QADOCS_LOGGER)

    def __init__(self, config):
        """Class constructor

        Initialize every attribute.

        Args:
            config (Config): A `Config` instance with the loaded configuration.
        """
        self.conf = config
        self.pytest = PytestWrap()
        self.function_regexes = []
        for regex in self.conf.function_regex:
            self.function_regexes.append(re.compile(regex))

    def is_documentable_function(self, function):
        """Check if a specific method matches with the regexes to be documented.

        Args:
            function (_ast.FunctionDef): Function class with all the information of the method.

        Returns:
            boolean: A boolean with True if the method should be documented. False otherwise
        """
        for regex in self.function_regexes:
            if regex.match(function.name):
                return True
        return False

    def remove_ignored_fields(self, doc):
        """Remove the fields from a parsed module file to delete the fields that are not mandatory or optional.

        It may disappear because the fields that are parsed and not specified in the `qa-docs` schema raise an error.

        Args:
            doc (dict): A dict that contains the parsed documentation block"
        """
        allowed_fields = self.conf.module_fields.mandatory + self.conf.module_fields.optional \
                                                           + self.conf.module_fields.auto + INTERNAL_FIELDS
        remove_inexistent(doc, allowed_fields, STOP_FIELDS)

        if 'tests' in doc:
            allowed_fields = self.conf.test_fields.mandatory + self.conf.test_fields.optional + INTERNAL_FIELDS

            for test in doc['tests']:
                remove_inexistent(test, allowed_fields, STOP_FIELDS)

    def check_fields(self, doc, doc_type, path):
        """Check if the fields that a documentation block has, are valids.

        You can check them in the `schema.yaml` file.

        Args:
            doc (dict): A dict with the documentation block parsed.
            doc_type (str): A string that specifies which type of documentation block is.
            path (str): A string with the file path.
        """
        if doc_type == 'module':
            expected_fields = self.conf.module_fields
        elif doc_type == 'test':
            expected_fields = self.conf.test_fields

        # check that mandatory fields are documented
        for field in expected_fields.mandatory:
            if field not in doc.keys():
                CodeParser.LOGGER.error(f"{field} mandatory field is missing.")
                raise QAValueError(f"{field} mandatory field is missing.", CodeParser.LOGGER.error)

        # check that only schema fields are documented
        for field in doc.keys():
            if field not in expected_fields.mandatory and field not in expected_fields.optional \
               and field not in expected_fields.auto and field != 'name':
                CodeParser.LOGGER.error(f"{field} is not specified in qa-docs schema.")
                raise QAValueError(f"{field} is not specified in qa-docs schema.", CodeParser.LOGGER.error)

    def check_predefined_values(self, doc, doc_type, path):
        """Check if the documentation block follows the predefined values.

        It iterates through the predefined values and checks if the documentation fields contain correct values.
        If the field does not exist or does not contain a predefined value, it would log it.

        The predefined values are stored in
        https://github.com/wazuh/wazuh-qa/wiki/Documenting-tests-using-the-qadocs-schema#pre-defined-values.

        Args:
            doc (dict): A dict with the documentation block parsed.
            doc_type (str): A string that specifies which type of documentation block is.
            path (str): A string with the file path.
        """
        for field in self.conf.predefined_values[f"{doc_type}_fields"]:
            try:
                doc_field = doc[field]
            except KeyError:
                doc_field = None

            # If the field is a list, iterate thru predefined values
            if isinstance(doc_field, list):
                for value in doc_field:
                    if value not in self.conf.predefined_values[field]:
                        CodeParser.LOGGER.error(f"{field} field in {path} {doc_type} documentation block has "
                                                f"an invalid value: {value}."
                                                f"Follow the predefined values: {self.conf.predefined_values[field]}. "
                                                "If you want more info, visit https://github.com/wazuh/wazuh-qa/wiki/"
                                                "Documenting-tests-using-the-qadocs-schema#pre-defined-values.")
                        raise QAValueError(f"{field} field in {path} {doc_type} documentation block has "
                                           f"an invalid value: {value}.", CodeParser.LOGGER.error)
            else:
                if doc_field not in self.conf.predefined_values[field] and doc_field is not None:
                    CodeParser.LOGGER.error(f"{field} field in {path} {doc_type} documentation block "
                                            f"has an invalid value: {doc_field}. "
                                            f"Follow the predefined values: {self.conf.predefined_values[field]} "
                                            "If you want more info, visit https://github.com/wazuh/wazuh-qa/wiki/"
                                            "Documenting-tests-using-the-qadocs-schema#pre-defined-values.")
                    raise QAValueError(f"{field} field in {path} {doc_type} documentation block "
                                       f"has an invalid value: {doc_field}.", CodeParser.LOGGER.error)

    def parse_comment(self, function, doc_type, path):
        """Parse one self-contained documentation block.

        Args:
            function (_ast.FunctionDef): Function class with all the information of the method"
            doc_type (str): A string that specifies which type of documentation block is.
            path (str): A string with the file path.

        Returns:
            doc (dict): A dictionary with the documentation block parsed.
        """
        docstring = ast.get_docstring(function)
        if not docstring:
            CodeParser.LOGGER.error(f"Documentation block not found in {path}")
            raise QAValueError(f"Documentation block not found in {path}", CodeParser.LOGGER.error)

        try:
            doc = yaml.safe_load(docstring)

            if hasattr(function, 'name'):
                doc['name'] = function.name

        except Exception as inst:
            if hasattr(function, 'name'):
                CodeParser.LOGGER.error(f"Failed to parse test documentation in {function.name} "
                                        f"from module {self.scan_file}. Error: {inst}")
                raise QAValueError(f"Failed to parse test documentation in {function.name} "
                                   f"from module {self.scan_file}. Error: {inst}", CodeParser.LOGGER.error)
            else:
                CodeParser.LOGGER.error(f"Failed to parse module documentation in  {self.scan_file}. Error: {inst}")
                raise QAValueError(f"Failed to parse module documentation in  {self.scan_file}. Error: {inst}",
                                   CodeParser.LOGGER.error)

        CodeParser.LOGGER.debug(f"Checking that the documentation block within {path} follow the predefined values.")
        self.check_predefined_values(doc, doc_type, path)
        self.check_fields(doc, doc_type, path)

        return doc

    def parse_module(self, path, id, group_id):
        """Parse the content of a module file.

        Args:
            path (str): A string with the path of the module file to be parsed.
            id (str): An integer with the ID of the new module document.
            group_id (int): An integer with the ID of the group where the new module document belongs.

        Returns:
            module_doc (dict): A dictionary with the documentation block parsed with module and tests fields.
        """
        CodeParser.LOGGER.debug(f"Parsing module file '{path}'")
        self.scan_file = path
        with open(path) as fd:
            file_content = fd.read()
        module = ast.parse(file_content)
        functions = [node for node in module.body if isinstance(node, ast.FunctionDef)]

        module_doc = self.parse_comment(module, 'module', path)
        if module_doc:
            module_doc['name'] = os.path.basename(path)
            module_doc['id'] = id
            module_doc['group_id'] = group_id

            # If the path is specified within the documentation block, it logs an error
            if 'path' in module_doc.keys():
                CodeParser.LOGGER.error('Path field is an autogenerated field, you must not specify it.')
                raise QAValueError('Path field is an autogenerated field, you must not specify it.',
                                   CodeParser.LOGGER.error)

            module_doc['path'] = re.sub(r'.*wazuh-qa\/', '', path)

            functions_doc = []
            for function in functions:
                if self.is_documentable_function(function):
                    function_doc = self.parse_comment(function, 'test', path)

                    if function_doc:
                        if 'inputs' not in function_doc:
                            test_cases = self.pytest.collect_test_cases(path)
                            if test_cases and test_cases[function.name]:
                                function_doc['inputs'] = test_cases[function.name]
                        # ES throwing errors because of the expected_output format in some cases
                        # -> Inserting the raw string and its comment between double quotes fixes it
                        if 'expected_output' in function_doc:
                            new_expected_output = []
                            for string in function_doc['expected_output']:
                                if isinstance(string, dict):
                                    for key, value in string.items():
                                        # example: r'.*Sending: FIM event (.+)$' ('added', 'modified' events)
                                        new_expected_output.append(f"{key}: {value}")
                                else:
                                    new_expected_output.append(f"{string}")
                            function_doc['expected_output'] = new_expected_output

                        functions_doc.append(function_doc)

            if not functions_doc:
                CodeParser.LOGGER.error(f"Module '{module_doc['name']}' doesn´t contain any test function")
                raise QAValueError(f"Module '{module_doc['name']}' doesn´t contain any test function",
                                   CodeParser.LOGGER.error)
            else:
                module_doc['tests'] = functions_doc

            self.remove_ignored_fields(module_doc)

        return module_doc

    def parse_group(self, group_file, id, group_id):
        """Parse the content of a group file.

        Args:
            group_file (str): A string with the path of the group file to be parsed.
            id (int): An integer with the ID of the new module document.
            group_id (int): An integer with the ID of the group where the new module document belongs.

        Returns:
            group_doc (dict): A dictionary with the parsed information from `group_file`.
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
