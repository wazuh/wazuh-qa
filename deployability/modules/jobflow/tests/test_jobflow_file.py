# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""JobFlowFile unit tests."""
from typing import Any, List
from unittest.mock import patch, MagicMock, call, mock_open
import pytest

from jobflow.jobflow_processor import JobFlowFile


def test_jobflow_file_constructor():
    """Test JobFlowFile constructor.
    Check the function calls and instance variables after object creation."""
    with patch("jobflow.jobflow_processor.JobFlowFile._JobFlowFile__validate_schema") as validate_mock, \
         patch("jobflow.jobflow_processor.JobFlowFile._JobFlowFile__load_workflow",
               return_value={'data': 'data'}) as load_mock, \
         patch("jobflow.jobflow_processor.JobFlowFile._JobFlowFile__process_workflow") as process_mock, \
         patch("jobflow.jobflow_processor.JobFlowFile._JobFlowFile__static_workflow_validation") \
            as static_validation_mock:
        wf = JobFlowFile(jobflow_file_path='my_file.yaml', schema_path='my_schema.yaml')
    assert wf.schema_path == 'my_schema.yaml'
    validate_mock.assert_called_once_with('my_file.yaml')
    load_mock.assert_called_once_with('my_file.yaml')
    assert wf.jobflow_raw_data == {'data': 'data'}
    process_mock.assert_called_once()
    static_validation_mock.assert_called_once()


@pytest.mark.parametrize('logger_mock', [{}], indirect=True)
def test_jobflow_file_validate_schema(logger_mock: MagicMock):
    """Test JobFlowFile.__validate_schema.
    Check debug messages and function called by the method.

    Parameters
    ----------
    logger_mock : MagicMock
        The logger fixture defined in conftest.py.
    """
    wf = MagicMock()
    wf.schema_path = 'my_schema_path.yaml'
    jobflow_file = 'my_file_path.yaml'
    schema_validator = MagicMock()
    with patch('jobflow.jobflow_processor.SchemaValidator', 
               return_value=schema_validator) as schema_validator_mock:
         with patch.object(schema_validator, 'preprocess_data') as preprocess_mock, \
              patch.object(schema_validator, 'validateSchema') as validate_schema_mock:
             JobFlowFile._JobFlowFile__validate_schema(self=wf, jobflow_file=jobflow_file)

    logger_mock.debug.assert_called_once_with(f"Validating input file: {jobflow_file}")
    schema_validator_mock.assert_called_once_with(wf.schema_path, jobflow_file)
    preprocess_mock.assert_called_once()
    validate_schema_mock.assert_called_once()


@pytest.mark.parametrize('logger_mock', [{}], indirect=True)
def test_jobflow_file_validate_schema_ko(logger_mock: MagicMock):
    """Test JobFlowFile.__validate_schema error flow.
    Check logged messages and function calls of the method.

    Parameters
    ----------
    logger_mock : MagicMock
        The logger fixture defined in conftest.py.
    """
    wf = MagicMock()
    wf.schema_path = 'my_schema_path.yaml'
    jobflow_file = 'my_file_path.yaml'
    file_exc = FileNotFoundError()
    with patch('jobflow.jobflow_processor.SchemaValidator', side_effect=file_exc) as schema_validator_mock, \
         pytest.raises(FileNotFoundError):
        JobFlowFile._JobFlowFile__validate_schema(self=wf, jobflow_file=jobflow_file)

    logger_mock.debug.assert_called_once_with(f"Validating input file: {jobflow_file}")
    schema_validator_mock.assert_called_once_with(wf.schema_path, jobflow_file)
    logger_mock.error.assert_called_once_with("Error while validating schema [%s] with error: %s",
                                              wf.schema_path,
                                              file_exc)


@pytest.mark.parametrize('logger_mock', [{}], indirect=True)
@patch('builtins.open', new_callable=mock_open, read_data='YAML content')
def test_jobflow_file_load_jobflow(mock_open: MagicMock, logger_mock: MagicMock):
    """Test JobFlowFile.__load_workflow.
    Check logged messages and function calls of the method.
    
    Parameters
    ----------
    mock_open : MagicMock
        The mock fixture defined in conftest.py.
    logger_mock : MagicMock
        The logger fixture defined in conftest.py.
    """
    wf = MagicMock()
    wf.schema_path = 'my_schema_path.yaml'
    jobflow_file = 'my_file_path.yaml'
    mock_open.return_value.__enter__.return_value = mock_open
    with patch('jobflow.jobflow_processor.os.path.exists', return_value=True) as path_exists_mock, \
         patch('jobflow.jobflow_processor.yaml.safe_load') as safe_load_mock:
        JobFlowFile._JobFlowFile__load_workflow(self=wf, file_path=jobflow_file)

    path_exists_mock.assert_called_once_with(jobflow_file)
    logger_mock.debug.assert_called_once_with(f"Loading workflow file: {jobflow_file}")
    mock_open.assert_called_once_with(jobflow_file, 'r', encoding='utf-8')
    safe_load_mock.assert_called_once_with(mock_open)


@pytest.mark.parametrize('logger_mock', [{}], indirect=True)
@patch('builtins.open', new_callable=mock_open, read_data='YAML content')
def test_jobflow_file_load_jobflow_ko(mock_open: MagicMock, logger_mock: MagicMock):
    """Test JobFlowFile.__load_workflow error flow.
    Check if the FileNotFoundError exception is raised by the method.

    Parameters
    ----------
    mock_open : MagicMock
        unittest mock of the open function
    logger_mock : MagicMock
        The logger fixture defined in conftest.py
    """
    wf = MagicMock()
    wf.schema_path = 'my_schema_path.yaml'
    jobflow_file = 'my_file_path.yaml'
    mock_open.return_value.__enter__.return_value = mock_open
    with patch('jobflow.jobflow_processor.os.path.exists', return_value=False) as path_exists_mock, \
         pytest.raises(FileNotFoundError, match=f'File "{jobflow_file}" not found.') as file_exc:
        JobFlowFile._JobFlowFile__load_workflow(self=wf, file_path=jobflow_file)


@pytest.mark.parametrize('logger_mock', [{}], indirect=True)
def test_jobflow_file_process_jobflow(logger_mock: MagicMock):
    """Test JobFlowFile.__process_workflow.
    Check that the method calls the expand_task method of each task using a lambda as a side effect.

    Parameters
    ----------
    logger_mock : MagicMock
        The logger fixture defined in conftest.py
    """
    variable_list = {'variable_1': 'value_1', 'variable_2': 'value_2'}
    task_list = [{'task': 'task1'}, {'task': 'task2'}, {'task': 'task3'}]
    expanded_task_list = [{'task': 'task3_1'}, {'task': 'task3_2'}]
    wf = MagicMock()
    wf.jobflow_raw_data = {'tasks': task_list, 'variables': variable_list}
    wf._JobFlowFile__expand_task.side_effect = lambda task, variables: [task] + \
        (expanded_task_list if task['task'] == 'task3' else [])
    tasks = JobFlowFile._JobFlowFile__process_workflow(wf)

    logger_mock.debug.assert_called_once_with("Process workflow.")
    calls = [call(task, variable_list) for task in task_list]
    wf._JobFlowFile__expand_task.assert_has_calls(calls)
    task_list.extend(expanded_task_list)
    assert tasks == task_list


@pytest.mark.parametrize('logger_mock', [{}], indirect=True)
def test_jobflow_file_process_jobflow_ok(logger_mock: MagicMock):
    """Test JobFlowFile.__process_workflow error flow.
    Check that a ValueError is raised when no task are found in the JobFlow.

    Parameters
    ----------
    logger_mock : MagicMock
        The logger fixture defined in conftest.py
    """
    wf = MagicMock()
    wf.jobflow_row_data = {
        'tasks': []
    }
    wf.__expand_task.return_value = []
    with pytest.raises(ValueError, match="No tasks found in the workflow."):
        tasks = JobFlowFile._JobFlowFile__process_workflow(self=wf)

    logger_mock.debug.assert_called_once_with("Process workflow.")


@pytest.mark.parametrize('element, values, return_value',
                         [({'key_1': 'key_1 {value_1}', 'key_2': 'key_2 {value_2}'},
                           {'value_1': 'value_1', 'value_2': 'value_2'},
                           {'key_1': 'key_1 value_1', 'key_2': 'key_2 value_2'}),
                          (['element_1 {value_1}', 'element_2 {value_2}', 'element_3 {value_3}'],
                           {'value_1': 'value_1', 'value_2': 'value_2', 'value_3': 'value_3'},
                           ['element_1 value_1', 'element_2 value_2', 'element_3 value_3']),
                          ('string_element {value}', {'value': 'value'}, 'string_element value'),
                          ({1, 2}, None, {1, 2})])
def test_jobflow_file_replace_placeholder(element: Any, values: dict, return_value: Any):
    """Test JobFlowFile.__replace_placeholder."""
    wf = MagicMock()
    wf._JobFlowFile__replace_placeholders.side_effect = \
        lambda s, e, v: JobFlowFile._JobFlowFile__replace_placeholders(wf, s, e, v)
    result = JobFlowFile._JobFlowFile__replace_placeholders(self=wf, element=element, values=values)
    assert result == return_value


@pytest.mark.parametrize('task, return_value, variables',
                         [({'task': 'task: {as_variable_1}', 'param': '{as_variable_2}',
                            'foreach': [{'variable': 'variable_1', 'as': 'as_variable_1'},
                                        {'variable': 'variable_2', 'as': 'as_variable_2'}]},
                           [{"task": "task: value_1_1", 'param': 'value_2_1',
                             "foreach": [{"variable": "variable_1", "as": "as_variable_1"},
                                         {"variable": "variable_2", "as": "as_variable_2"}]},
                            {"task": "task: value_1_1", 'param': 'value_2_2',
                             "foreach": [{"variable": "variable_1", "as": "as_variable_1"},
                                         {"variable": "variable_2", "as": "as_variable_2"}]},
                            {"task": "task: value_1_2", 'param': 'value_2_1',
                             "foreach": [{"variable": "variable_1", "as": "as_variable_1"},
                                         {"variable": "variable_2", "as": "as_variable_2"}]},
                            {"task": "task: value_1_2", 'param': 'value_2_2',
                             "foreach": [{"variable": "variable_1", "as": "as_variable_1"},
                                         {"variable": "variable_2", "as": "as_variable_2"}]}],
                            {'variable_1': ['value_1_1', 'value_1_2'],
                             'variable_2': ['value_2_1', 'value_2_2']}),
                           ({'task': 'task1', 'placeholder': 'placeholder {variable_1}'},
                            [{'task': 'task1', 'placeholder': 'placeholder value_1'}],
                             {'variable_1': 'value_1'})
                           ])
def test_jobflow_file_expand_task(task: dict, return_value: dict, variables: dict):
    """Test JobFlowFile.___expand_task.
    Check the if the expand_task return dictionary is ok.

    Parameters
    ----------
    task : dict
        A task dictionary used as the input parameter for the expand_task method.
    return_value : dict
        The expected return value.
    variables : dict
        The variables dictionary used as the input parameter for the expand_task method.
    """
    def side_effect(s, e, v = None):
        return JobFlowFile._JobFlowFile__replace_placeholders(wf, s, e, v)
    wf = MagicMock()
    wf._JobFlowFile__replace_placeholders.side_effect = side_effect

    tasks = JobFlowFile._JobFlowFile__expand_task(wf, task, variables)
    assert tasks == return_value


def test_jobflow_file_static_jobflow_validation():
    """Test JobFlowFile.__static_workflow_validation.
    Check if no exception is raised with a valid task_collection"""
    wf = MagicMock()
    wf.task_collection = [{"task": "task 1", "param": "1"},
                          {"task": "task 2", "param": "2", 'depends-on': ['task 1']}
        ]
    JobFlowFile._JobFlowFile__static_workflow_validation(wf)


@pytest.mark.parametrize('task_collection, error_msg', [
    ([{"task": "task 1", "param": "1"},
     {"task": "task 1", "param": "2", 'depends-on': ['task 1']}],
     'Duplicated task names: task 1'), 
    ([{"task": "task 1", "param": "1", 'depends-on': ['task 3', 'task 4']},
     {"task": "task 2", "param": "2", 'depends-on': ['task 3']}],
     'Tasks do not exist: task 3, task 4') 
])
def test_jobflow_file_static_jobflow_validation_ko(task_collection: List[dict], error_msg: str):
    """Test JobFlowFile.__static_workflow_validation.
    Check if the validation raises ValueError exceptions with invalid task collections.
    
    Parameters
    ----------
    task_collection : List[dict]
        List of tasks
    error_msg : str
        Expected exception errors
    """
    wf = MagicMock()
    wf.task_collection = task_collection
    with pytest.raises(ValueError, match=error_msg):
        JobFlowFile._JobFlowFile__static_workflow_validation(wf)
