import yaml
import logging

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
        self.module_fields = self.__fields()
        self.test_fields = self.__fields()
        self.test_cases_field = None

        try:
            with open(CONFIG_PATH) as fd:
                self.__config_data = yaml.safe_load(fd)
        except:
            logging.error("Cannot load config file")
            raise Exception("Cannot load config file")

        self.__read_project_path()
        self.__read_documentation_path()
        self.__read_include_paths()
        self.__read_include_regex()
        self.__read_group_files()
        self.__read_function_regex()
        self.__read_ignore_paths()
        self.__read_valid_tags()
        self.__read_output_fields()
        self.__read_test_cases_field()

    def __read_project_path(self):
        if 'Project path' in self.__config_data:
            self.project_path = self.__config_data['Project path']

    def __read_documentation_path(self):
        if 'Output path' in self.__config_data:
            self.documentation_path = self.__config_data['Output path']

    def __read_include_paths(self):
        if not 'Include paths' in self.__config_data:
            logging.error("Config include paths are empty")
            raise Exception("Config include paths are empty")
        self.include_paths = self.__config_data['Include paths']

    def __read_include_regex(self):
        if not 'Include regex' in self.__config_data:
            logging.error("Config include regex is empty")
            raise Exception("Config include regex is empty")
        self.include_regex = self.__config_data['Include regex']

    def __read_group_files(self):
        if not 'Group files' in self.__config_data:
            logging.error("Config group files is empty")
            raise Exception("Config group files is empty")
        self.group_files = self.__config_data['Group files']

    def __read_function_regex(self):
        if not 'Function regex' in self.__config_data:
            logging.error("Config function regex is empty")
            raise Exception("Config function regex is empty")
        self.function_regex = self.__config_data['Function regex']

    def __read_ignore_paths(self):
        if 'Ignore paths' in self.__config_data:
            self.ignore_paths = self.__config_data['Ignore paths']

    def __read_valid_tags(self):
        if 'Valid tags' in self.__config_data:
            self.valid_tags = self.__config_data['Valid tags']

    def __read_module_fields(self):
        if not 'Module' in self.__config_data['Output fields']:
            logging.error("Config output module fields is missing")
            raise Exception("Config output module fields is missing")
        module_fields = self.__config_data['Output fields']['Module']
        if not 'Mandatory' in module_fields and not 'Optional' in module_fields:
            logging.error("Config output module fields are empty")
            raise Exception("Config output module fields are empty")
        if 'Mandatory' in module_fields:
            self.module_fields.mandatory = module_fields['Mandatory']
        if 'Optional' in module_fields:
            self.module_fields.optional = module_fields['Optional']

    def __read_test_fields(self):
        if not 'Test' in self.__config_data['Output fields']:
            logging.error("Config output test fields is missing")
            raise Exception("Config output test fields is missing")
        test_fields = self.__config_data['Output fields']['Test']
        if not 'Mandatory' in test_fields and not 'Optional' in test_fields:
            logging.error("Config output test fields are empty")
            raise Exception("Config output test fields are empty")
        if 'Mandatory' in test_fields:
            self.test_fields.mandatory = test_fields['Mandatory']
        if 'Optional' in test_fields:
            self.test_fields.optional = test_fields['Optional']

    def __read_output_fields(self):
        if not 'Output fields' in self.__config_data:
            logging.error("Config output fields is missing")
            raise Exception("Config output fields is missing")
        self.__read_module_fields()
        self.__read_test_fields()

    def __read_test_cases_field(self):
        if 'Test cases field' in self.__config_data:
            self.test_cases_field = self.__config_data['Test cases field']
    class __fields:
        def __init__(self):
            self.mandatory = []
            self.optional = []
