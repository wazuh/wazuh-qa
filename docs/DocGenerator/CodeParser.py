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

INTERNAL_FIELDS = ['Id', 'Group Id', 'Name']
STOP_FIELDS = ['Tests','Test Cases']

class CodeParser:
    def __init__(self):
        self.conf = Config()
        self.pytest = PytestWrap()
        self.function_regexes = []
        for regex in self.conf.function_regex:
            self.function_regexes.append(re.compile(regex))

    def is_documentable_function(self, function):
        for regex in self.function_regexes:
            if regex.match(function.name):
                return True
        return False

    def remove_ignored_fields(self, doc):
        allowed_fields = self.conf.module_fields.mandatory + self.conf.module_fields.optional + INTERNAL_FIELDS
        remove_inexistent(doc, allowed_fields, STOP_FIELDS)
        if 'Tests' in doc:
            allowed_fields = self.conf.test_fields.mandatory + self.conf.test_fields.optional + INTERNAL_FIELDS
            for test in doc['Tests']:
                remove_inexistent(test, allowed_fields, STOP_FIELDS)

    def parse_comment(self, function):
        docstring = ast.get_docstring(function)
        try:
            doc = yaml.safe_load(docstring)
            if hasattr(function, 'name'):
                doc['Name'] = function.name

        except Exception as inst:
            if hasattr(function, 'name'):
                warnings.warn(f"Failed to parse comment of function '{function.name}'' from module {self.scan_file}", stacklevel=2)
                logging.warning(f"Failed to parse comment of function '{function.name}'' from module {self.scan_file}")
            else:
                warnings.warn(f"Failed to parse comment of module {self.scan_file}", stacklevel=2)
                logging.warning(f"Failed to parse comment of module {self.scan_file}")
            doc = None

        return doc

    def parse_test(self, code_file, id, group_id):
        logging.debug(f"Parsing test file '{code_file}'")
        self.scan_file = code_file
        with open(code_file) as fd:
            file_content = fd.read()
        module = ast.parse(file_content)
        functions = [node for node in module.body if isinstance(node, ast.FunctionDef)]

        module_doc = self.parse_comment(module)
        if module_doc:
            module_doc['Name'] = os.path.basename(code_file)
            module_doc['Id'] = id
            module_doc['Group Id'] = group_id

            test_cases = self.pytest.collect_test_cases(code_file)
            functions_doc = []
            for function in functions:
                if self.is_documentable_function(function):
                    function_doc = self.parse_comment(function)
                    if function_doc:
                        if test_cases[function.name]:
                            function_doc["Test Cases"] = test_cases[function.name]
                        functions_doc.append(function_doc)

            if not functions_doc:
                warnings.warn(f"Module '{module_doc['Name']}' doesn´t contain any test function", stacklevel=2)
                logging.warning(f"Module '{module_doc['Name']}' doesn´t contain any test function")
            else:
                module_doc['Tests'] = functions_doc

            self.remove_ignored_fields(module_doc)

        return module_doc

    def parse_group(self, group_file, id, group_id):
        logging.debug(f"Parsing group file '{group_file}'")
        with open(group_file) as fd:
            file_content = fd.read()
        group_doc = {}
        group_doc['Name'] = os.path.basename(os.path.dirname(group_file))
        group_doc['Id'] = id
        group_doc['Group id'] = group_id
        group_doc['Description'] = file_content

        return group_doc
