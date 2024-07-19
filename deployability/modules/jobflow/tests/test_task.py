# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
from typing import List, Tuple
from subprocess import CompletedProcess, CalledProcessError
from unittest.mock import patch, MagicMock, call
import pytest

from jobflow.task import ProcessTask

@pytest.fixture
def task(request) -> ProcessTask:
    """Shared fixture to create task."""
    task_name, task_parms = request.param
    return ProcessTask(task_name=task_name, task_parameters=task_parms)


@pytest.mark.parametrize("task", [('task1', {"param1": "value1"})], indirect=True)
def test_process_task_constructor(task: ProcessTask):
    """Test ProcessTask constructor.
    Check the task instance varialbes after constructing the ProcessTask.

    Parameters
    ----------
    task : ProcessTask
        The task fixture.
    """
    assert task.task_name == 'task1'
    assert task.task_parameters == {"param1": "value1"}


@pytest.mark.parametrize("task", [('task1', {"path": "/mypath",
                                             "args": [{"param1": "value1"}]}),
                                  ('task2', {"path": "/mypath",
                                             "args": ["param1"]}),
                                  ('task3', {"path": "/mypath",
                                             "args": ["param1", "param2"]}),
                                  ('task4', {"path": "/mypath",
                                             "args": ["param1", {"param2": "value2"}]}),
                                  ('task5', {"path": "/mypath",
                                             "args": [{"param1": "value1"}, {"param2": "value2"}]})
                                  ], indirect=True)
@patch("jobflow.task.logger")
def test_process_task_execute(logger_mock: MagicMock, task: ProcessTask):
    """Test ProcessTask.execute method normal flow.
    Check that ProcessTask.execute calls subprocess.run to run commands with the defined parameters. The
    task mock in conftest.py is used to thy diferent command argument formats.

    Parameters
    ----------
    logger_mock : MagicMock
        The logger mock defined in conftest.py
    task : ProcessTask
        The task fixture.
    """
    results = {}
    results["task1"] = {"parm_list": [task.task_parameters['path'],  "--param1=value1"]}
    results["task2"] = {"parm_list": [task.task_parameters['path'], "param1"]}
    results["task3"] = {"parm_list": [task.task_parameters['path'], "param1", "param2"]}
    results["task4"] = {"parm_list": [task.task_parameters['path'], "param1",
                                      "--param2=value2"]}
    results["task5"] = {"parm_list": [task.task_parameters['path'], "--param1=value1",
                                      "--param2=value2"]}
    result = CompletedProcess(args=results[task.task_name]["parm_list"][1:],
                              returncode=0, stdout="command output",
                              stderr="")
    debug_calls = [call(f'Running task "{task.task_name}" with arguments: '
                        f'{results[task.task_name]["parm_list"][1:]}')]
    with patch("jobflow.task.subprocess.run", return_value=result) as proc_run_mock, \
         patch.object(logger_mock, "debug") as logger_debug_mock:
        debug_calls.append(call(f'Finished task "{task.task_name}" execution '
                                f'with result:\n{str(result.stdout)}'))
        task.execute()

        logger_debug_mock.assert_has_calls(debug_calls)
        proc_run_mock.assert_called_once_with(results[task.task_name]['parm_list'], check=True,
                                              capture_output=True, text=True)


@pytest.mark.parametrize("task", [('task1', {"path": "/mypath",
                                             "args": [{"param1": "value1"}]}),
                                  ], indirect=True)
@pytest.mark.parametrize("subproc_retval", [1, 0])
@pytest.mark.parametrize("subproc_run_exc", [(True, KeyboardInterrupt, "KeyboardInterrupt error"),
                                             (True, Exception, "Other Error")])
def test_process_task_execute_ko(subproc_retval: int, subproc_run_exc: List[Tuple], task: ProcessTask):
    """Test ProcessTask.execute method exception flows.
    Check ProcessTask.execute flow when the subprocess.run returns errors.

    Parameters
    ----------
    subproc_retval : int
        return code from subprocess.run
    subproc_run_exc : bool
        Tuple
    task : ProcessTask
        The task fixture.
    """
    raise_exc, exception_type, stderr = subproc_run_exc
    if exception_type is Exception:
        match = f"Error executing process task {stderr}"
    else:
        match = "Error executing process task with keyboard interrupt."
    result = CompletedProcess(args=["--param1=value1"],
                              returncode=subproc_retval, stdout="command output",
                              stderr=stderr)
    with patch("jobflow.task.subprocess.run", return_value=result) as proc_run_mock:
        if raise_exc:
            proc_run_mock.side_effect = CalledProcessError(returncode=1,
                                                           cmd=task.task_parameters['path'],
                                                           stderr=stderr)

        with pytest.raises(exception_type, match=match):
            task.execute()
