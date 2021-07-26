import ast
import os
import re
import json
import yaml
from Config import Config
from TestCaseParser import TestCaseParser
from docstring_parser import parse
from comment_parser import comment_parser
import warnings

class CodeParser:
    def __init__(self):
        self.conf = Config()
        self.test_case_parser = TestCaseParser()
        self.function_regexes = []
        for regex in self.conf.function_regex:
            self.function_regexes.append(re.compile(regex))

    def is_documentable_function(self, function):
        for regex in self.function_regexes:
            if regex.match(function.name):
                return True
        return False

    def remove_ignored_fields(self, doc):
        for field in self.conf.ignored_fields.module:
            if field in doc:
                del doc[field]
        for test in doc['Tests']:
            for field in self.conf.ignored_fields.tests:
                if field in test:
                    del test[field]

    def parse_comment(self, function):
        docstring = ast.get_docstring(function)
        try:
            doc = yaml.load(docstring)
            if hasattr(function, 'name'):
                doc['Name'] = function.name

        except Exception as inst:
            warnings.warn("Error parsing comment of...")
            print(type(inst))
            print(inst.args)
            print(inst)
            doc = None

        return doc

    def parse_test(self, code_file, id, group_id):
        with open(code_file) as fd:
            file_content = fd.read()
        module = ast.parse(file_content)
        functions = [node for node in module.body if isinstance(node, ast.FunctionDef)]

        module_doc = self.parse_comment(module)
        if module_doc:
            module_doc['Name'] = os.path.basename(code_file)
            module_doc['Id'] = id
            module_doc['Group Id'] = group_id

            test_cases = self.test_case_parser.collect(code_file)

            functions_doc = []
            for function in functions:
                if self.is_documentable_function(function):
                    function_doc = self.parse_comment(function)
                    if function_doc:
                        if test_cases[function.name]:
                            function_doc["Test Cases"] = test_cases[function.name]
                        functions_doc.append(function_doc)

            if not functions_doc:
                warnings.warn("Module doesn´t contain any test function")

            module_doc['Tests'] = functions_doc

            #self.remove_ignored_fields(module_doc)

        return module_doc

    def parse_group(self, group_file, id, group_id):
        with open(group_file) as fd:
            file_content = fd.read()
        group_doc = {}
        group_doc['Name'] = os.path.basename(os.path.dirname(group_file))
        group_doc['Id'] = id
        group_doc['Group id'] = group_id
        group_doc['Description'] = file_content

        return group_doc
