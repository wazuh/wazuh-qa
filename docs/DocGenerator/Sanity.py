from Config import Config
import os
import re
import json
import ast


class Sanity():
    def __init__(self,):
        self.conf = Config()
        self.files_regex = re.compile("^(?!.*group)test.*json$", re.IGNORECASE)
        self.error_reports = []
        self.found_tags = set()
        self.found_tests = set()
        self.found_modules = set()
        self.project_tests = 0

    def get_content(self, full_path):
        try:
            with open(full_path) as file:
                return json.load(file)
        except:
            raise Exception(f"Cannot load {full_path} file")

    def validate_fields(self, required_fields, available_fields):
        for field in required_fields:
            if isinstance(field, dict):
                for key in field:
                    if key in available_fields:
                        self.validate_fields(field[key], available_fields[key])
                    else:
                        self.add_report(f"Mandatory field '{key}' is missing in file {self.scan_file}")
            elif not field in available_fields:
                self.add_report(f"Mandatory field '{field}' is missing in file {self.scan_file}")


    def validate_module_fields(self, fields):
        self.validate_fields(self.conf.module_fields.mandatory, fields)

    def validate_test_fields(self, fields):
        for test_fields in fields['Tests']:
            self.validate_fields(self.conf.test_fields.mandatory, test_fields)

    def identify_tags(self, content):
        if 'Tags' in content['Metadata']:
            for tag in content['Metadata']['Tags']:
                self.found_tags.add(tag)

    def identify_tests(self, content):
        if 'Tests' in content:
            for test in content['Tests']:
                self.found_tests.add(test['Name'])

    def count_project_tests(self):
        file_regexes = []
        function_regexes = []
        for regex in self.conf.include_regex:
            file_regexes.append(re.compile(regex))
        for regex in self.conf.function_regex:
            function_regexes.append(re.compile(regex))

        for (root, directories, files) in os.walk(self.conf.project_path, topdown=True):
            for regex in file_regexes:
                test_files = list(filter(regex.match, files))
                for test_file in test_files:
                    with open(os.path.join(root,test_file)) as fd:
                        file_content = fd.read()
                    module = ast.parse(file_content)
                    functions = [node for node in module.body if isinstance(node, ast.FunctionDef)]
                    for function in functions:
                        for regex in function_regexes:
                            if regex.match(function.name):
                                self.project_tests = self.project_tests + 1



    def add_report(self, message):
        self.error_reports.append(message)

    def print_report(self):
        print("")
        print("During the sanity check:")

        print("")
        if self.error_reports:
            print("The following errors were found:")
            for error in self.error_reports:
                print("- "+error)
        else:
            print("No errors were found:")

        if self.found_tags:
            print("")
            print("The following tags were found:")
            for tag in self.found_tags:
                print("- "+tag)

        print("")
        modules_count = len(self.found_modules)
        tests_count = len(self.found_tests)
        tests_percentage = tests_count / self.project_tests * 100
        print(f"A total of {len(self.found_tests)} tests were found in {modules_count} modules")
        print("A {:.2f}% from the tests of {} is covered.".format(tests_percentage, self.conf.project_path))

    def run(self):
        for (root, directories, files) in os.walk(self.conf.documentation_path, topdown=True):
            files = list(filter(self.files_regex.match, files))
            for file in files:
                full_path = os.path.join(root, file)
                content = self.get_content(full_path)
                if content:
                    self.scan_file = full_path
                    self.validate_module_fields(content)
                    self.validate_test_fields(content)
                    self.identify_tags(content)
                    self.identify_tests(content)
                    self.found_modules.add(content['Name'])

        self.count_project_tests()
        self.print_report()

sanity = Sanity()
sanity.run()
