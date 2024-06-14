# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
"""Common unit test fixtures."""
import graphlib

from unittest.mock import patch, MagicMock
import pytest

from jobflow.jobflow_processor import DAG, JobFlowProcessor

DEFAULT_TASK_COLLECTION = [
    {'task': 'task1', 'path': '/cmd1', 'args': [{"param1": "value1"}]},
    {'task': 'task2', 'path': '/cmd2', 'args': [{"param1": "value1"}]},
    {'task': 'task3', 'path': '/cmd3', 'args': [{"param1": "value1"}]},
]


@pytest.fixture
def logger_mock(request) -> MagicMock:
    """Fixture to mock common logger methods."""
    logger_to_patch = request.param.get('logger_to_patch', "jobflow.jobflow_processor.logger")
    with patch(logger_to_patch) as l_mock:
        patch.object(l_mock, 'warning')
        patch.object(l_mock, 'info')
        patch.object(l_mock, 'debug')
        patch.object(l_mock, 'error')
        yield l_mock


@pytest.fixture
def dag(request) -> DAG:
    """Create a mocked DAG instance."""
    ret_dag: DAG
    reverse = request.param.get('reverse', False)
    task_collection = request.param.get('task_collection', DEFAULT_TASK_COLLECTION)
    if request.param.get('patch', True):
        execution_plan_dict = request.param.get('execution_plan_dict', {})
        gl_dag = graphlib.TopologicalSorter()
        dep_dict = {'task1': 'task2'}
        with patch.object(gl_dag, 'prepare'), \
            patch('jobflow.jobflow_processor.DAG._DAG__build_dag',
                return_value=(gl_dag, dep_dict)), \
            patch('jobflow.jobflow_processor.DAG._DAG__create_execution_plan',
                return_value=execution_plan_dict):
            ret_dag = DAG(task_collection=task_collection, reverse=reverse)
    else:
        ret_dag = DAG(task_collection=task_collection, reverse=reverse)

    if finished_task_status := request.param.get('finished_task_status', False):
        ret_dag.finished_tasks_status = finished_task_status

    return ret_dag


@pytest.fixture
def w_processor(request) -> JobFlowProcessor:
    """Create a mocked JobFlowProcessor instance."""

    jobflow_file = request.param.get('jobflow_file', 'jobflow.yaml')
    dry_run = request.param.get('dry_run', False)
    threads = request.param.get('threads', 1)
    log_level = request.param.get('log_level', 'info')
    schema_file = request.param.get('schema_file', 'schema.yaml')
    with patch("jobflow.jobflow_processor.JobFlowFile") as file_mock:
        jobflow_file_instance = file_mock.return_value
        jobflow_file_instance.task_collection = request.param.get('task_collection', DEFAULT_TASK_COLLECTION)
        if request.param.get('patch', True):
            with patch('jobflow.jobflow_processor.logger.setLevel'):
                processor = JobFlowProcessor(jobflow_file, dry_run, threads,
                                              log_level, schema_file)
        else:
            processor = JobFlowProcessor(jobflow_file, dry_run,
                                          threads, log_level, schema_file)
    return processor
