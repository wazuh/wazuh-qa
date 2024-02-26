# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""SchemaValidator unit tests."""
import uuid
import random
from pathlib import Path
from unittest.mock import MagicMock, call, patch
import json
from ruamel.yaml import YAML
import pytest
from jsonschema.exceptions import ValidationError, UnknownType

from workflow_engine.schema_validator import SchemaValidator

@pytest.mark.parametrize('logger_mock',
                         [{'logger_to_patch':'workflow_engine.schema_validator.logger'}],
                         indirect=True)
def test_schema_validator_constructor(logger_mock: MagicMock):
    """Test SchemaValidator constructor normal flow."""
    schema_path = Path(__file__).parent.parent / 'schemas' / 'schema_v1.json'
    with open(schema_path, 'r') as schema_file:
        schema_data = json.load(schema_file)

    wf_file_path = Path(__file__).parent / 'data' / 'wf-ok.yml'
    with open(wf_file_path, 'r') as file:
        yaml = YAML(typ='safe', pure=True)
        yaml_data = yaml.load(file)

    validator = SchemaValidator(schema_path, wf_file_path)
    assert validator.schema_data == schema_data
    assert validator.yaml_data == yaml_data
    calls = [call(f"Loading schema file: {schema_path}"), 
             call(f"Loading yaml file: {wf_file_path}")]
    logger_mock.debug.assert_has_calls(calls)


@pytest.mark.parametrize('logger_mock',
                         [{'logger_to_patch':'workflow_engine.schema_validator.logger'}],
                         indirect=True)
def test_schema_validator_constructor_ko(logger_mock: MagicMock):
    """Test SchemaValidator constructor error flows."""
    schema_path = str(uuid.UUID(int=random.randint(0, 2^32)))
    with pytest.raises(FileNotFoundError, match=f'File "{schema_path}" not found.'):
        SchemaValidator(schema_path, schema_path)


def test_preprocess_data():
    """Test SchemaValidator preprocess_data."""
    schema_path = Path(__file__).parent.parent / 'schemas' / 'schema_v1.json'
    wf_file_path = Path(__file__).parent / 'data' / 'wf-ok.yml'
    validator = SchemaValidator(schema_path, wf_file_path)
    validator.preprocess_data()


@pytest.mark.parametrize('workflow_file, error_msg',
                         [('wf-ko-no-path-on-do.yml',
                           "Missing required properties in 'with' for task: {'task': 'run-agent-tests-{agent}'"),
                          ('wf-ko-no-path-on-cleanup.yml',
                           "Missing required properties in 'with' for task: {'task': 'allocate-manager'"),])
def test_preprocess_data_ko(workflow_file: str, error_msg: str):
    """Test SchemaValidator preprocess_data error flow."""
    schema_path = Path(__file__).parent.parent / 'schemas' / 'schema_v1.json'
    wf_file_path = Path(__file__).parent / 'data' / workflow_file
    validator = SchemaValidator(schema_path, wf_file_path)
    with pytest.raises(ValidationError, match=error_msg):
        validator.preprocess_data()


def test_validate_schema():
    """Test SchemaValidator validate_schema."""
    schema_path = Path(__file__).parent.parent / 'schemas' / 'schema_v1.json'
    wf_file_path = Path(__file__).parent / 'data' / 'wf-ok.yml'
    validator = SchemaValidator(schema_path, wf_file_path)
    validator.validateSchema()


@pytest.mark.parametrize('logger_mock',
                         [{'logger_to_patch':'workflow_engine.schema_validator.logger'}],
                         indirect=True)
def test_validate_schema_ko(logger_mock: MagicMock):
    """Test SchemaValidator validate_schema error flows."""
    schema_path = Path(__file__).parent.parent / 'schemas' / 'schema_v1.json'
    wf_file_path = Path(__file__).parent / 'data' / 'wf-ko-schema-error.yml'
    validator = SchemaValidator(schema_path, wf_file_path)
    validator.validateSchema()
    logger_mock.error.assert_called_once()
    assert 'Schema validation error:' in logger_mock.error.call_args[0][0]

    logger_mock.error.reset_mock()
    validator = SchemaValidator(schema_path, wf_file_path)
    with patch('workflow_engine.schema_validator.jsonschema.validate', side_effect=UnknownType):
        validator.validateSchema()
    logger_mock.error.assert_called_once()
    assert 'Unexpected error at schema validation:' in logger_mock.error.call_args[0][0]
