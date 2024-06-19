# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
import jsonschema
import json
import os

from jsonschema.exceptions import ValidationError
from pathlib import Path
from ruamel.yaml import YAML

from jobflow.logger.logger import logger

class SchemaValidator:
    """
    A SchemaValidator class that validates a YAML file against a JSON schema.

    Attributes:
        schema_data (dict): The schema data.
        yaml_data (dict): The YAML data.
    """

    def __init__(self, schema: Path | str, to_validate: Path | str):
        """
        Initializes the SchemaValidator object.

        Args:
            schema (Path, str): The path to the schema file.
            to_validate (Path, str): The path to the YAML file to validate.
        """
        schema_data: str = None
        yaml_data: str = None

        self.logger = logger

        if not os.path.exists(schema):
            raise FileNotFoundError(f'File "{schema}" not found.')

        with open(schema, 'r') as schema_file:
            self.logger.debug(f"Loading schema file: {schema}")
            schema_data = json.load(schema_file)

        if not os.path.exists(to_validate):
            raise FileNotFoundError(f'File "{to_validate}" not found.')

        with open(to_validate, 'r') as file:
            self.logger.debug(f"Loading yaml file: {to_validate}")
            yaml = YAML(typ='safe', pure=True)
            yaml_data = yaml.load(file)

        self.schema_data = schema_data
        self.yaml_data = yaml_data

    def preprocess_data(self) -> None:
        """
        Preprocess the YAML data to be validated.

        Raises:
            ValidationError: If the YAML data is not valid.
        """
        for task in self.yaml_data.get('tasks', []):
            do_with = task.get('do', {}).get('with', {})
            this_value = task.get('do', {}).get('this', '')

            if this_value == 'process':
                if 'path' not in do_with or 'args' not in do_with:
                    raise ValidationError(f"Missing required properties in 'with' for task: {task}")

            do_with = task.get('cleanup', {}).get('with', {})
            this_value = task.get('cleanup', {}).get('this', '')

            if this_value == 'process':
                if 'path' not in do_with or 'args' not in do_with:
                    raise ValidationError(f"Missing required properties in 'with' for task: {task}")

    def validateSchema(self) -> None:
        """
        Validate the JobFlow schema

        Raises:
            ValidationError: If the YAML data is not valid.
            Exception: If an unexpected error occurs.
        """
        try:
            jsonschema.validate(self.yaml_data, self.schema_data)
        except ValidationError as e:
            self.logger.error(f"Schema validation error: {e}")
        except Exception as e:
            self.logger.error(f"Unexpected error at schema validation: {e}")
