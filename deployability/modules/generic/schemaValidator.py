import jsonschema
from ruamel.yaml import YAML
import json

class SchemaValidator:


    # -------------------------------------
    #   Constructor
    # -------------------------------------

    def __init__(self, shcema, yamlToValidate):
        schemaData = ""
        yamlData = ""
        with open(shcema, 'r') as schema_file:
            schemaData = json.load(schema_file)

        with open(yamlToValidate, 'r') as file:
            yaml = YAML(typ='safe', pure=True)
            yamlData = yaml.load(file)

        self.schemaData = schemaData
        self.yamlData = yamlData

    def preprocess_data(self):
        for task in self.yamlData.get('tasks', []):
            do_with = task.get('do', {}).get('with', {})
            this_value = task.get('do', {}).get('this', '')

            if this_value == 'process':
                if 'path' not in do_with or 'args' not in do_with:
                    raise jsonschema.exceptions.ValidationError(f"Missing required properties in 'with' for task: {task}")

            do_with = task.get('cleanup', {}).get('with', {})
            this_value = task.get('cleanup', {}).get('this', '')

            if this_value == 'process':
                if 'path' not in do_with or 'args' not in do_with:
                    raise jsonschema.exceptions.ValidationError(f"Missing required properties in 'with' for task: {task}")

    def validateSchema(self):
        """
        Validate the Workflow schema
        """
        try:
            jsonschema.validate(self.yamlData, self.schemaData)
        except jsonschema.exceptions.ValidationError as e:
            print(f"Validation error: {e}")
        except Exception as e:
            print(f"Error: {e}")