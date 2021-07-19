import ast
import os
import re
import json
import yaml
from Config import Config
from docstring_parser import parse
from comment_parser import comment_parser
import warnings

TEST_PARENT_PATH="/home/palacios/Workspace/wazuh-qa/tests"
TEST_PATH=os.path.join(TEST_PARENT_PATH, "integration", "test_wazuh_db","test_wazuh_db.py")
SCRIPT_PATH=os.getcwd()
module_name = os.path.basename(TEST_PATH)

class CodeParser:
    def __init__(self):
        self.conf = Config()
        self.function_regexes = []
        for regex in self.conf.function_regex:
            self.function_regexes.append(re.compile(regex))

    def is_documentable_function(self, function):
        for regex in self.function_regexes:
            if regex.match(function.name):
                return True
        return False

    def parse_comment(self, function):
        docstring = ast.get_docstring(function)
        try:
            doc = yaml.load(docstring)
            if hasattr(function, 'name'):
                doc['name'] = function.name
            else:
                doc['name'] = self.module_name

        except Exception as inst:
            warnings.warn("Error parsing comment of...")
            print(type(inst))
            print(inst.args)
            print(inst)
            doc = None

        return doc

    def parse(self, code_file):
        self.module_name = os.path.basename(code_file)
        with open(code_file) as fd:
            file_content = fd.read()
        module = ast.parse(file_content)
        functions = [node for node in module.body if isinstance(node, ast.FunctionDef)]

        module_doc = self.parse_comment(module)
        print(module_doc)
        print(yaml.dump(module_doc))

        functions_doc = []
        for function in functions:
            if self.is_documentable_function(function):
                function_doc = self.parse_comment(function)
                if function_doc is not None:
                    functions_doc.append(function_doc)
        if not functions_doc:
            warnings.warn("Module doesn´t contain any test function")

        module_doc['tests'] = functions_doc

        return module_doc

code_parser = CodeParser()
ret = code_parser.parse(TEST_PATH)

print(ret)
print(yaml.dump(ret))

with open(os.path.join(SCRIPT_PATH,"{module_name}.json"), "w") as fd:
    fd.write(json.dumps(ret))

with open(os.path.join(SCRIPT_PATH,"{module_name}.yaml"), "w") as fd:
    fd.write(yaml.dump(ret))
