import os
import re
import json
import ast
import config as config

conf = config.Config()


class Documentation:
    def __init__(self, ignore_folders, include_paths, include_regex, documentation_path):
        self.ignore_folders = ignore_folders
        self. include_paths = include_paths
        self.include_regex = include_regex
        self.documentation_path = documentation_path

    def get_readme(self, filepath):
        with open(filepath) as file:
            lines = file.readlines()
            return lines

    def dump_information(self, filepath, content):
        with open(filepath, "w") as outfile:
            outfile.write(content)

    def create_json_file_2(self, root, docs, filenames):
        # Iterate over al test files in the directory.
        for filename in filenames:
            full_path = os.path.join(root, filename)
            with open(full_path) as fd:
                # Read file content and extract module header and function docstrings
                file_contents = fd.read()
                module = ast.parse(file_contents)
                header = ast.get_docstring(module)
                function_definitions = [node for node in module.body if isinstance(node, ast.FunctionDef)]
                info = {
                    "header": header,
                    "test_functions": []
                }
                for function_definition in function_definitions:
                    if function_definition.name.startswith("test_"):
                        test_info = {
                            function_definition.name: ast.get_docstring(function_definition)
                        }
                        info["test_functions"].append(test_info)
                json_object = json.dumps(info, indent=4)
                json_file_path = os.path.join(docs, f"{filename[:-2]}json")
                self.dump_information(json_file_path, json_object)

    def create_json_file(self, root, docs, children, filename):
        # Get readme.md content.
        description = self.get_readme(os.path.join(root, filename))
        info = {
            "name": root.split(os.sep)[-1:][0],
            "elements": children,
            "description": description
        }
        json_object = json.dumps(info, indent=4)
        # Json filename uses the same name the folder that contains it.
        json_file_path = os.path.join(docs, f"{root.split(os.sep)[-1:][0]}_group.json")
        self.dump_information(json_file_path, json_object)

    def docs_tree_generator(self):
        for path in self.include_paths:
            for (root, directories, files) in os.walk(path.path, topdown=True):
                # Remove directories we don't want to check.
                for dir in self.ignore_folders:
                    if dir in directories:
                        directories.remove(dir)
                # Look for test.py and readme.md files
                regex = re.compile(self.include_regex[0], re.IGNORECASE)
                files = list(filter(regex.match, files))
                # Generate directory tree that constains either .py scripts or readme.md files.
                if len(files):
                    # Create directory tree
                    docs_path = [self.documentation_path]
                    for folder in root.split(os.sep):
                        if not folder.startswith(".."):
                            docs_path.append(folder)
                    docs_path = os.path.join(*docs_path)
                    os.makedirs(docs_path, exist_ok=True)
                    # For any readme.md file we create at the same level a .json file
                    readme_files = []
                    test_files = []
                    for file in files:
                        if file.upper() == "README.MD":
                            readme_files.append(file)
                        else:
                            test_files.append(file)
                    if len(readme_files):
                        self.create_json_file(root, docs_path, directories, readme_files[0])
                    if len(test_files):
                        self.create_json_file_2(root, docs_path, test_files)


docs = Documentation(conf.ignore_folders, conf.include_paths, conf.include_regex, conf.documentation_path)
docs.docs_tree_generator()
