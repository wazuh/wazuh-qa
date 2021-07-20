import config
import sys
import os
import re
import json

conf = config.Config()


class InvalidJsonFormat(Exception):
    pass


class InvalidTag(Exception):
    pass


class ModuleFieldNotFound(Exception):
    pass


class MetadataFieldNotFound(Exception):
    pass


class TestFieldNotFound(Exception):
    pass


class Sanity():
    def __init__(self, documentation_path, module_required_fields, tests_required_fields, valid_tags):
        self.documentation_path = documentation_path
        self.regex = "^(?!.*group)test.*json$"
        self.module_required_fields = module_required_fields
        self.tests_required_fields = tests_required_fields
        self.valid_tags = valid_tags

    def get_content(self, full_path):
        with open(full_path) as file:
            try:
                return json.load(file)
            except InvalidJsonFormat:
                pass

    def validate_module_fields(self, file, header):
        fields = list(header.keys())
        lst = []
        metadata_fields = []
        metadata_lst = []
        for field in self.module_required_fields:
            if '.' not in field:
                if not field.upper() in [temp.upper() for temp in fields]:
                    lst.append(field)
            else:
                metadata_fields.append(field.split('.')[1])
        if len(lst):
            raise ModuleFieldNotFound(f"For {file} {lst} must be present")
        for key in fields:
            if key.upper() == "METADATA":
                for field in metadata_fields:
                    if not field.upper() in [temp.upper() for temp in list(header[key].keys())]:
                        metadata_lst.append(field)
        if len(metadata_lst):
            raise MetadataFieldNotFound(f"For {file} {metadata_lst} must be present")

    def validate_test_fields(self, file, header):
        lst = []
        keys = list(header.keys())
        for k in keys:
            if k.upper() == "TESTS":
                tests_fields = list(header[k][0].keys())
                for field in self.tests_required_fields:
                    if not field.upper() in [temp.upper() for temp in tests_fields]:
                        lst.append(field)
        if len(lst):
            raise TestFieldNotFound(f"For {file} {lst} must be present")

    def validate_tags(self, file, header):
        lst = []
        keys = list(header.keys())
        for k in keys:
            if k.upper() == "TAGS":
                tags = header[k]
                for field in self.valid_tags:
                    if not field.upper() in [temp.upper() for temp in tags]:
                        lst.append(field)
        if len(lst):
            raise InvalidTag(f"For {file} {lst} is not correct")

    def validate(self, path, files):
        for file in files:
            full_path = os.path.join(path, file)
            content = self.get_content(full_path)
            header = content
            self.validate_module_fields(file, header)
            self.validate_test_fields(file, header)
            self.validate_tags(file, header)

    def get_files(self):
        for (root, directories, files) in os.walk(self.documentation_path, topdown=True):
            regex = re.compile(self.regex, re.IGNORECASE)
            files = list(filter(regex.match, files))
            if len(files):
                self.validate(root, files)

    def sanity(self):
        self.get_files()


sanity = Sanity(conf.documentation_path, conf.required_fields.module, conf.required_fields.tests, conf.valid_tags)
sanity.sanity()
