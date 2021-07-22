from collections import namedtuple
import yaml

CONFIG_PATH = "config.yaml"


class Config():
    def __init__(self):
        self.project_path = "../.."
        self.documentation_path = ".."
        self.include_paths = []
        self.include_regex = []
        self.group_files = ""
        self.function_regex = []
        self.ignore_paths = []
        self.valid_tags = []
        self.required_fields = self.__fields()
        self.ignored_fields = self.__fields()
        with open(CONFIG_PATH) as fd:
            self.__config_data = yaml.load(fd)

        self.__read_project_path()
        self.__read_documentation_path()
        self.__read_include_paths()
        self.__read_include_regex()
        self.__read_group_files()
        self.__read_function_regex()
        self.__read_ignore_paths()
        self.__read_valid_tags()
        self.__read_required_fields()
        self.__read_ignored_fields()

    def __read_project_path(self):
        if 'Project path' in self.__config_data:
            self.project_path = self.__config_data['Project path']

    def __read_documentation_path(self):
        if 'Documentation path' in self.__config_data:
            self.documentation_path = self.__config_data['Documentation path']

    def __read_include_paths(self):
        if not 'Include paths' in self.__config_data:
            raise Exception("Include paths are empty")
        for include in self.__config_data['Include paths']:
            if not 'path' in include:
                raise Exception("One include path is missing")
            element = self.__paths()
            element.path = include['path']
            if 'recursive' in include:
                element.recursive = include['recursive']
            self.include_paths.append(element)

    def __read_include_regex(self):
        if not 'Include regex' in self.__config_data:
            raise Exception("Include regex is empty")
        self.include_regex = self.__config_data['Include regex']

    def __read_group_files(self):
        if not 'Group files' in self.__config_data:
            raise Exception("Group files is empty")
        self.group_files = self.__config_data['Group files']

    def __read_function_regex(self):
        if not 'Function regex' in self.__config_data:
            raise Exception("Function regex is empty")
        self.function_regex = self.__config_data['Function regex']

    def __read_ignore_paths(self):
        if 'Ignore paths' in self.__config_data:
            self.ignore_paths = self.__config_data['Ignore paths']

    def __read_valid_tags(self):
        if 'Valid tags' in self.__config_data:
            self.valid_tags = self.__config_data['Valid tags']

    def __read_required_fields(self):
        if 'Required fields' in self.__config_data:
            required_fields = self.__config_data['Required fields']
            if 'Module' in required_fields:
                for required_module_field in required_fields['Module']:
                    self.required_fields.module.append(required_module_field)
            if 'Tests' in required_fields:
                for required_tests_field in required_fields['Tests']:
                    self.required_fields.tests.append(required_tests_field)
            if 'Case Sensitive' in required_fields:
                self.required_fields.case_sensitive = required_fields['Case Sensitive']

    def __read_ignored_fields(self):
        if 'Ignored fields' in self.__config_data:
            ignored_fields = self.__config_data['Ignored fields']
            if 'Module' in ignored_fields:
                for required_module_field in ignored_fields['Module']:
                    self.ignored_fields.module.append(required_module_field)
            if 'Tests' in ignored_fields:
                for required_tests_field in ignored_fields['Tests']:
                    self.ignored_fields.tests.append(required_tests_field)
            if 'Case Sensitive' in ignored_fields:
                self.ignored_fields.case_sensitive = ignored_fields['Case Sensitive']

    class __paths:
        def __init__(self):
            self.path = []
            self.recursive = True

    class __fields:
        def __init__(self):
            self.module = []
            self.tests = []
            self.case_sensitive = False
