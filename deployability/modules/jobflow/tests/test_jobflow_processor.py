# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""JobFlowProcessor Unit tests"""
import time
import json
from concurrent.futures import Future
from unittest.mock import patch, MagicMock, call
import pytest

from jobflow.jobflow_processor import JobFlowProcessor, DAG
from jobflow.task import ProcessTask, TASKS_HANDLERS


@pytest.mark.parametrize('jobflow_file, dry_run, threads, log_level, schema_file',
                         [('jobflow.yaml', False, 1, 'info', 'schema.yaml'),
                          ('jobflow.yaml', True, 1, 'debug', 'schema.yaml'),
                          ('jobflow.yaml', True, 1, 'debug', None),
                          ])
@patch("jobflow.jobflow_processor.logger")
@patch("jobflow.jobflow_processor.JobFlowFile")
def test_jobflow_processor_constructor(file_mock: MagicMock, logger_mock: MagicMock,
                                        jobflow_file:str, dry_run: bool, threads: int, log_level: str,
                                        schema_file:str):
    """Test JobFlowProcessor constructor.
    Check the JobFlowProcessor instance variables after construction.

    Parameters
    ----------
    file_mock : MagicMock
        Mock of a JobFlowFile Constructor.
    logger_mock : MagicMock
        The logger fixture defined in conftest.py.
    jobflow_file : str
        Path to jobflow yaml file.
    dry_run : bool
        Define if the jobflow will run or not
    threads : int
        number of threads
    log_level : str
        Log level string
    schema_file : str
        Path to the schema.yml file
    """
    task_collection = [
        {'task': 'task1', 'path': '/cmd1', 'args': [{"param1": "value1"}]},
        {'task': 'task2', 'path': '/cmd2', 'args': [{"param1": "value1"}]},
        {'task': 'task3', 'path': '/cmd3', 'args': [{"param1": "value1"}]},
    ]
    jobflow_file_instance = file_mock.return_value
    jobflow_file_instance.task_collection = task_collection
    with patch.object(logger_mock, 'setLevel') as set_level_mock:
        processor = JobFlowProcessor(jobflow_file, dry_run, threads, log_level, schema_file)
    set_level_mock.assert_called_once_with(log_level)
    file_mock.assert_called_once_with(jobflow_file, schema_file)
    assert processor.task_collection == task_collection
    assert processor.dry_run == dry_run
    assert processor.threads == threads


@pytest.mark.parametrize('logger_mock, w_processor, dag, action, should_be_canceled',
                         [({}, {}, {}, 'custom_action', True),
                          ({}, {}, {}, 'custom_action', False),],
                         indirect=["dag", "w_processor", "logger_mock"])
def test_execute_task(logger_mock: MagicMock, w_processor: JobFlowProcessor, dag: DAG, action: str,
                      should_be_canceled: bool):
    """Test WorflowProcessor.execute_task function normal
    Check the execute_task method when log messages and function calls when the should_be_canceled return value 
    is True or False.

    Parameters
    ----------
    logger_mock : MagicMock
        The logger fixture defined in conftest.py.
    w_processor : JobFlowProcessor
        The JobFlow processor fixture defined in conftest.py.
    dag : DAG
        The dag  fixture defined in conftest.py.
    action : str
        action name
    should_be_canceled : bool
        should_be_canceled method patched return value.

    Returns
    -------
    [type]
        [description]
    """
    start_time = time.time()
    elapsed_time = 10
    def time_side_effect():
        nonlocal start_time
        start_time=start_time + elapsed_time
        return start_time

    task = {'task': 'task1'}
    p_task = ProcessTask('task1', {})
    with patch.object(dag, 'should_be_canceled', return_value=should_be_canceled) as should_be_canceled_mock, \
         patch.object(w_processor, 'create_task_object', return_value=p_task) as create_task_mock, \
         patch.object(dag, 'set_status') as set_status_mock, \
         patch.object(p_task, 'execute') as exec_mock, \
         patch('jobflow.jobflow_processor.time') as time_mock:
        time_mock.time = MagicMock(side_effect=time_side_effect)
        w_processor.execute_task(dag=dag, task=task, action=action)
        should_be_canceled_mock.assert_called_once_with(task['task'])
        if should_be_canceled:
            logger_mock.warning.assert_called_once_with(
                "[%s] Skipping task due to dependency failure.", task['task'])
            set_status_mock.assert_called_once_with(task['task'], 'canceled')
        else:
            create_task_mock.assert_called_once_with(task, action)
            exec_mock.assert_called_once()
            logger_mock.info.assert_has_calls([
                    call("[%s] Starting task.", task['task']),
                    call("[%s] Finished task in %.2f seconds.", task['task'], elapsed_time)
                ]
            )
            set_status_mock.assert_called_once_with(task['task'], 'successful')


@pytest.mark.parametrize('on_error', [None, 'abort-all'])
@pytest.mark.parametrize('logger_mock, w_processor, dag, exception',
                         [({}, {}, {}, KeyboardInterrupt),
                          ({}, {}, {}, Exception)],
                         indirect=["dag", "w_processor", "logger_mock"])
def test_execute_task_ko(logger_mock: MagicMock, w_processor: JobFlowProcessor, dag: DAG, exception,
                         on_error: str):
    """Test WorflowProcessor.execute_task function, error flows.
    Check logged messages, set_status call and cancel_dependant_tasks in the failure flow.

    Parameters
    ----------
    logger_mock : MagicMock
        The logger fixture defined in conftest.py.
    w_processor : JobFlowProcessor
        The JobFlow processor fixture defined in conftest.py.
    dag : DAG
        The dag  fixture defined in conftest.py.
    exception : [type]
        Expected exception.
    on_error : str
        set on-error of the task.
    """
    task = {'task': 'task1'}
    task.update({'on-error': on_error} if on_error else {})
    p_task = ProcessTask('task1', {})
    exc = exception()
    with patch.object(dag, 'should_be_canceled', return_value=False), \
         patch.object(w_processor, 'create_task_object', return_value=p_task), \
         patch.object(dag, 'set_status') as set_status_mock, \
         patch.object(p_task, 'execute', side_effect=exc), \
         patch('jobflow.jobflow_processor.time'), \
         patch.object(dag, 'cancel_dependant_tasks') as cancel_mock, \
         pytest.raises(expected_exception=exception):
        w_processor.execute_task(dag=dag, task=task, action='action')

    logger_mock.error.assert_called_once_with("[%s] Task failed with error: %s.", task['task'], exc)
    set_status_mock.assert_called_once_with(task['task'], 'failed')
    cancel_mock.assert_called_once_with(task['task'], on_error if on_error else 'abort-related-flows')


@pytest.mark.parametrize('task_type', ['process', 'dummy', 'dummy-random'])
@pytest.mark.parametrize('w_processor', [{}], indirect=True)
def test_create_task_object(w_processor: JobFlowProcessor, task_type: str):
    """Test WorkfowProcess.create_task_object function normal flow.
    Check the task type returned by the method.

    Parameters
    ----------
    w_processor : JobFlowProcessor
        The JobFlow processor fixture defined in conftest.py.
    task_type : str
        type of task
    """
    task_dict = {'task': 'task1', 'action': {'this': task_type, 'with': {'param'}}}
    task = w_processor.create_task_object(task_dict, 'action')
    assert isinstance(task, TASKS_HANDLERS.get(task_type))


@pytest.mark.parametrize('w_processor', [{}], indirect=True)
def test_create_task_object_ko(w_processor: JobFlowProcessor):
    """Test WorkfowProcess.create_task_object function error flow.
    Check that the create_task_object raise a ValueError exception for invalid types.}

    Parameters
    ----------
    w_processor : JobFlowProcessor
        The JobFlow processor fixture defined in conftest.py.
    """
    task_type = 'unknown'
    task_dict = {'task': 'task1', 'action': {'this': task_type, 'with': {'param'}}}
    with pytest.raises(ValueError, match=f"Unknown task type '{task_type}'."):
        w_processor.create_task_object(task_dict, 'action')


@pytest.mark.parametrize('reverse', [False, True])
@pytest.mark.parametrize('logger_mock, w_processor, dag',[({}, {}, {})],
                         indirect=["dag", "w_processor", "logger_mock"])
@patch('jobflow.jobflow_processor.concurrent.futures.ThreadPoolExecutor')
def test_execute_tasks_parallel(executor_mock: MagicMock, logger_mock: MagicMock, w_processor: JobFlowProcessor,
                                dag: DAG, reverse: bool):
    """Test WorkfowProcess.execute_task_parallel function.
    Check if the logged messages and function calls of the method with reverse True and False cases.

    Parameters
    ----------
    executor_mock : MagicMock
        Mock of the ThreadPoolExecutor.
    logger_mock : MagicMock
        The logger fixture defined in conftest.py.
    w_processor : JobFlowProcessor
        The JobFlow processor fixture defined in conftest.py.
    dag : DAG
        The dag fixture defined in conftest.py.
    reverse : bool
        Parameterized value for the execute__tasks_parallel reverse parameter.
    """
    futures = MagicMock()
    futures.values = MagicMock(return_value = (x := MagicMock()))
    y = MagicMock()
    y.__enter__ = MagicMock(return_value=y)
    executor_mock.return_value = y
    with patch('jobflow.jobflow_processor.concurrent.futures.wait') as wait_mock, \
         patch.object(w_processor, 'generate_futures', return_value=futures) as gen_futures_mock:
        w_processor.execute_tasks_parallel(dag, reverse=reverse)
    logger_mock.info.assert_called_once_with("Executing tasks in parallel.")
    executor_mock.assert_called_once_with(max_workers=w_processor.threads)
    wait_mock.assert_called_once_with(x)
    gen_futures_mock.assert_called_once_with(dag, y, reverse)


@pytest.mark.parametrize('reverse', [False, True])
@pytest.mark.parametrize('logger_mock, w_processor, dag',[({}, {}, {})],
                         indirect=["dag", "w_processor", "logger_mock"])
@patch('jobflow.jobflow_processor.concurrent.futures.ThreadPoolExecutor')
def test_execute_tasks_parallel_ko(executor_mock: MagicMock, logger_mock: MagicMock, w_processor: JobFlowProcessor,
                                dag: DAG, reverse: bool):
    """Test WorkfowProcess.execute_task_parallel function error flow.
    Check function call message loggin and calls when the KeyboardInterrupt is generated while waiting the subprocess
    to finish execution.

    Parameters
    ----------
    executor_mock : MagicMock
        not used, just patched
    logger_mock : MagicMock
        The logger fixture defined in conftest.py.
    w_processor : JobFlowProcessor
        The JobFlow processor fixture defined in conftest.py.
    dag : DAG
        The dag fixture defined in conftest.py.
    reverse : bool
        Parameterized value for the execute__tasks_parallel reverse parameter.
    """
    execute_parallel_mock = MagicMock()
    def patch_recursive_and_return_exception(_):
        w_processor.execute_tasks_parallel = execute_parallel_mock
        raise KeyboardInterrupt()

    with patch('jobflow.jobflow_processor.concurrent.futures.wait',
               side_effect=patch_recursive_and_return_exception), \
         patch.object(w_processor, 'generate_futures'):
        w_processor.execute_tasks_parallel(dag, reverse=reverse)
    logger_mock.info.assert_called_once_with("Executing tasks in parallel.")
    logger_mock.error.assert_called_once_with("User interrupt detected. Aborting execution...")
    execute_parallel_mock.assert_called_once_with(dag, reverse=True)


@pytest.mark.parametrize('w_processor',
                         [{'task_collection': [
                                    {'task': 'task1'},
                                    {'task': 'task2', 'depends-on': ['task1']},
                                    {'task': 'task3', 'depends-on': ['task1']},
                                    {'task': 'task4', 'depends-on': ['task1']},
                                    {'task': 'task5', 'depends-on': ['task2', 'task3', 'task4']}],},
                         ],
                         indirect=True)
def test_generate_futures(w_processor: JobFlowProcessor):
    """Test WorkfowProcess.generate_futures function without reverse.
    Check the futures returned by the method.

    Parameters
    ----------
    w_processor : JobFlowProcessor
        The JobFlow processor fixture defined in conftest.py.
    """
    def submit_execute_task_side_effect(_, dag: DAG, task, __):
        dag.set_status(task['task'], 'successful')
        return Future()

    executor = MagicMock()
    executor.submit.side_effect=submit_execute_task_side_effect
    dag = DAG(task_collection=w_processor.task_collection)
    futures = w_processor.generate_futures(dag, executor=executor)
    assert len(futures) == len(w_processor.task_collection) and \
        all(isinstance(element, Future) for element in futures.values())


@pytest.mark.parametrize('w_processor',
                         [{'task_collection': [
                                    {'task': 'task1'},
                                    {'task': 'task2', 'depends-on': ['task1']},
                                    {'task': 'task3', 'depends-on': ['task1']},
                                    {'task': 'task4', 'depends-on': ['task1']},
                                    {'task': 'task5', 'depends-on': ['task2', 'task3', 'task4']}],},
                         ],
                         indirect=True)
def test_generate_futures_reverse(w_processor: JobFlowProcessor):
    """Test WorkfowProcess.generate_futures function with reverse True.
    Check that set_status with successful is called for the tasks.

    Parameters
    ----------
    w_processor : JobFlowProcessor
        The JobFlow processor fixture defined in conftest.py.
    """

    def set_status_side_effect(task, status):
        dag.finished_tasks_status[status].add(task)
        dag.dag.done(task)

    executor = MagicMock()
    dag = DAG(task_collection=w_processor.task_collection, reverse=True)
    with patch.object(dag, 'set_status', side_effect=set_status_side_effect) as set_status_mock:
        futures = w_processor.generate_futures(dag, executor=executor, reverse=True)
    calls = [call(task['task'], 'successful') for task in w_processor.task_collection]
    set_status_mock.assert_has_calls(calls, any_order=True)


@pytest.mark.parametrize('dry_run', [False, True])
@pytest.mark.parametrize('logger_mock, w_processor',
                         [({}, {
                            'task_collection': [
                                    {'task': 'task1'},
                                    {'task': 'task2', 'depends-on': ['task1']},
                                    {'task': 'task3', 'depends-on': ['task1']},
                                    {'task': 'task4', 'depends-on': ['task1']},
                                    {'task': 'task5', 'depends-on': ['task2', 'task3', 'task4']}],})],
                         indirect=True)
def test_run(logger_mock: MagicMock, w_processor: JobFlowProcessor, dry_run: bool):
    """Test WorkfowProcess.run function.
    Check log message and execute_tasks_parallel call.

    Parameters
    ----------
    logger_mock : MagicMock
        The logger fixture defined in conftest.py.
    w_processor : JobFlowProcessor
        The JobFlow processor fixture defined in conftest.py.
    dry_run : bool
        Parameterized value to test the run method.
    """
    def dag_constructor(_, reverse=False):
        return reverse_dag if reverse else dag

    w_processor.dry_run = dry_run
    dag = DAG(w_processor.task_collection)
    reverse_dag = DAG(w_processor.task_collection, reverse=True)
    with patch.object(w_processor, 'execute_tasks_parallel') as exec_tasks_mock, \
         patch('jobflow.jobflow_processor.DAG', side_effect=dag_constructor) as dag_mock:
        w_processor.run()
    if dry_run:
        dag_mock.assert_called_once_with(w_processor.task_collection)
        logger_mock.info.assert_called_once_with("Execution plan: %s", json.dumps(dag.get_execution_plan(), indent=2))
    else:
        logger_mock.info.assert_has_calls([call("Executing DAG tasks."), call("Executing Reverse DAG tasks.")])
        exec_tasks_mock.assert_has_calls([call(dag), call(reverse_dag, reverse=True)])
        dag_mock.assert_has_calls([call(w_processor.task_collection), call(w_processor.task_collection, reverse=True)])


@pytest.mark.parametrize('logger_mock, w_processor', [({}, {})], indirect=['logger_mock', 'w_processor'])
def test_handle_interrupt(logger_mock: MagicMock, w_processor: JobFlowProcessor):
    """Test WorkfowProcess.handle_interrupt function.
    Check logging when the handle_interrupt is called.
    
    Parameters
    ----------
    logger_mock : MagicMock
        The logger fixture defined in conftest.py.
    w_processor : JobFlowProcessor
        The JobFlow processor fixture defined in conftest.py.
    """
    with pytest.raises(KeyboardInterrupt, match="User interrupt detected. End process..."):
        w_processor.handle_interrupt(0, 0)
    logger_mock.error.assert_called_once_with("User interrupt detected. End process...")
