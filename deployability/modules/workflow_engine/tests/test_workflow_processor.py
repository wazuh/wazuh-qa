# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""WorkflowProcessor Unit tests"""
import time
import json
from concurrent.futures import Future
from unittest.mock import patch, MagicMock, call
import pytest

from workflow_engine.workflow_processor import WorkflowProcessor, DAG
from workflow_engine.task import ProcessTask, TASKS_HANDLERS


@pytest.mark.parametrize('workflow_file, dry_run, threads, log_level, schema_file',
                         [('workflow.yaml', False, 1, 'info', 'schema.yaml'),
                          ('workflow.yaml', True, 1, 'debug', 'schema.yaml'),
                          ('workflow.yaml', True, 1, 'debug', None),
                          ])
@patch("workflow_engine.workflow_processor.logger")
@patch("workflow_engine.workflow_processor.WorkflowFile")
def test_workflow_processor_constructor(file_mock: MagicMock, logger_mock: MagicMock,
                                        workflow_file, dry_run, threads, log_level, schema_file):
    """Test WorkflowProcessor constructor."""
    task_collection = [
        {'task': 'task1', 'path': '/cmd1', 'args': [{"param1": "value1"}]},
        {'task': 'task2', 'path': '/cmd2', 'args': [{"param1": "value1"}]},
        {'task': 'task3', 'path': '/cmd3', 'args': [{"param1": "value1"}]},
    ]
    workflow_file_instance = file_mock.return_value
    workflow_file_instance.task_collection = task_collection
    with patch.object(logger_mock, 'setLevel') as set_level_mock:
        processor = WorkflowProcessor(workflow_file, dry_run, threads, log_level, schema_file)
    set_level_mock.assert_called_once_with(log_level)
    file_mock.assert_called_once_with(workflow_file, schema_file)
    assert processor.task_collection == task_collection
    assert processor.dry_run == dry_run
    assert processor.threads == threads


@pytest.mark.parametrize('logger_mock, w_processor, dag, action, should_be_canceled',
                         [({}, {}, {}, 'custom_action', True),
                          ({}, {}, {}, 'custom_action', False),],
                         indirect=["dag", "w_processor", "logger_mock"])
def test_execute_task(logger_mock: MagicMock, w_processor: WorkflowProcessor, dag: DAG, action: str,
                      should_be_canceled: bool):
    """Test WorflowProcessor.execute_task function normal."""
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
         patch('workflow_engine.workflow_processor.time') as time_mock:
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
def test_execute_task_ko(logger_mock: MagicMock, w_processor: WorkflowProcessor, dag: DAG, exception,
                         on_error: str):
    """Test WorflowProcessor.execute_task function, error flows."""
    task = {'task': 'task1'}
    task.update({'on-error': on_error} if on_error else {})
    p_task = ProcessTask('task1', {})
    exc = exception()
    with patch.object(dag, 'should_be_canceled', return_value=False), \
         patch.object(w_processor, 'create_task_object', return_value=p_task), \
         patch.object(dag, 'set_status') as set_status_mock, \
         patch.object(p_task, 'execute', side_effect=exc), \
         patch('workflow_engine.workflow_processor.time'), \
         patch.object(dag, 'cancel_dependant_tasks') as cancel_mock, \
         pytest.raises(expected_exception=exception):
        w_processor.execute_task(dag=dag, task=task, action='action')

    logger_mock.error.assert_called_once_with("[%s] Task failed with error: %s.", task['task'], exc)
    set_status_mock.assert_called_once_with(task['task'], 'failed')
    cancel_mock.assert_called_once_with(task['task'], on_error if on_error else 'abort-related-flows')


@pytest.mark.parametrize('task_type', ['process', 'dummy', 'dummy-random'])
@pytest.mark.parametrize('w_processor', [{}], indirect=True)
def test_create_task_object(w_processor: WorkflowProcessor, task_type: str):
    """Test WorkfowProcess.create_task_object function normal flow."""
    task_dict = {'task': 'task1', 'action': {'this': task_type, 'with': {'param'}}}
    task = w_processor.create_task_object(task_dict, 'action')
    assert isinstance(task, TASKS_HANDLERS.get(task_type))


@pytest.mark.parametrize('w_processor', [{}], indirect=True)
def test_create_task_object_ko(w_processor: WorkflowProcessor):
    """Test WorkfowProcess.create_task_object function error flow."""
    task_type = 'unknown'
    task_dict = {'task': 'task1', 'action': {'this': task_type, 'with': {'param'}}}
    with pytest.raises(ValueError, match=f"Unknown task type '{task_type}'."):
        w_processor.create_task_object(task_dict, 'action')


@pytest.mark.parametrize('reverse', [False, True])
@pytest.mark.parametrize('logger_mock, w_processor, dag',[({}, {}, {})],
                         indirect=["dag", "w_processor", "logger_mock"])
@patch('workflow_engine.workflow_processor.concurrent.futures.ThreadPoolExecutor')
def test_execute_tasks_parallel(executor_mock: MagicMock, logger_mock: MagicMock, w_processor: WorkflowProcessor,
                                dag: DAG, reverse: bool):
    """Test WorkfowProcess.execute_task_parallel function."""
    futures = MagicMock()
    futures.values = MagicMock(return_value = (x := MagicMock()))
    y = MagicMock()
    y.__enter__ = MagicMock(return_value=y)
    executor_mock.return_value = y
    with patch('workflow_engine.workflow_processor.concurrent.futures.wait') as wait_mock, \
         patch.object(w_processor, 'generate_futures', return_value=futures) as gen_futures_mock:
        w_processor.execute_tasks_parallel(dag, reverse=reverse)
    logger_mock.info.assert_called_once_with("Executing tasks in parallel.")
    executor_mock.assert_called_once_with(max_workers=w_processor.threads)
    wait_mock.assert_called_once_with(x)
    gen_futures_mock.assert_called_once_with(dag, y, reverse)


@pytest.mark.parametrize('reverse', [False, True])
@pytest.mark.parametrize('logger_mock, w_processor, dag',[({}, {}, {})],
                         indirect=["dag", "w_processor", "logger_mock"])
@patch('workflow_engine.workflow_processor.concurrent.futures.ThreadPoolExecutor')
def test_execute_tasks_parallel_ko(executor_mock: MagicMock, logger_mock: MagicMock, w_processor: WorkflowProcessor,
                                dag: DAG, reverse: bool):
    """Test WorkfowProcess.execute_task_parallel function error flow."""
    execute_parallel_mock = MagicMock()
    def patch_recursive_and_return_exception(_):
        w_processor.execute_tasks_parallel = execute_parallel_mock
        raise KeyboardInterrupt()

    with patch('workflow_engine.workflow_processor.concurrent.futures.wait',
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
def test_generate_futures(w_processor: WorkflowProcessor):
    """Test WorkfowProcess.generate_futures function without reverse."""

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
def test_generate_futures_reverse(w_processor: WorkflowProcessor):
    """Test WorkfowProcess.generate_futures function with reverse True."""

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
def test_run(logger_mock: MagicMock, w_processor: WorkflowProcessor, dry_run: bool):
    """Test WorkfowProcess.run function."""
    def dag_constructor(_, reverse=False):
        return reverse_dag if reverse else dag

    w_processor.dry_run = dry_run
    dag = DAG(w_processor.task_collection)
    reverse_dag = DAG(w_processor.task_collection, reverse=True)
    with patch.object(w_processor, 'execute_tasks_parallel') as exec_tasks_mock, \
         patch('workflow_engine.workflow_processor.DAG', side_effect=dag_constructor) as dag_mock:
        w_processor.run()
    if dry_run:
        dag_mock.assert_called_once_with(w_processor.task_collection)
        logger_mock.info.assert_called_once_with("Execution plan: %s", json.dumps(dag.get_execution_plan(), indent=2))
    else:
        logger_mock.info.assert_has_calls([call("Executing DAG tasks."), call("Executing Reverse DAG tasks.")])
        exec_tasks_mock.assert_has_calls([call(dag), call(reverse_dag, reverse=True)])
        dag_mock.assert_has_calls([call(w_processor.task_collection), call(w_processor.task_collection, reverse=True)])


@pytest.mark.parametrize('logger_mock, w_processor', [({}, {})], indirect=['logger_mock', 'w_processor'])
def test_handle_interrupt(logger_mock: MagicMock, w_processor: WorkflowProcessor):
    """Test WorkfowProcess.handle_interrupt function."""
    with pytest.raises(KeyboardInterrupt, match="User interrupt detected. End process..."):
        w_processor.handle_interrupt(0, 0)
    logger_mock.error.assert_called_once_with("User interrupt detected. End process...")

