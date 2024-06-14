# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
import graphlib

from unittest.mock import patch, MagicMock, call
import pytest

from jobflow.jobflow_processor import DAG


@pytest.mark.parametrize("reverse", [True, False])
@patch("jobflow.jobflow_processor.DAG._DAG__build_dag")
@patch("jobflow.jobflow_processor.DAG._DAG__create_execution_plan")
def test_dag_constructor(create_exec_plan_mock: MagicMock, build_dag_mock: MagicMock, reverse: bool):
    """Test ProcessTask constructor
    Check all the dag object state after initialization and if the private dag methods are called during the instance
    construction.

    Parameters
    ----------
    create_exec_plan_mock : MagicMock
        Patch of the DAG.__create_execution_plan method.
    build_dag_mock : MagicMock
        Patch of the DAG.__build_dag_ method.
    reverse : bool
        Parametrized value used by the DAG constructor.
    """
    task_collection = [
        {'task': 'task1', 'path': '/cmd1', 'args': [{"param1": "value1"}]},
        {'task': 'task2', 'path': '/cmd2', 'args': [{"param1": "value1"}]},
        {'task': 'task3', 'path': '/cmd3', 'args': [{"param1": "value1"}]},
    ]
    gl_dag = graphlib.TopologicalSorter()

    dep_dict = {'task1': 'task2'}
    build_dag_mock.return_value = (gl_dag, dep_dict)
    plan_dict = {'task1', 'task2'}
    create_exec_plan_mock.return_value = plan_dict
    with patch.object(gl_dag, 'prepare') as prepare_mock:
        dag = DAG(task_collection=task_collection, reverse=reverse)

    assert dag.task_collection == task_collection
    assert dag.reverse == reverse
    assert dag.dag == gl_dag
    assert dag.dependency_tree == dep_dict
    assert isinstance(dag.to_be_canceled, set) and not dag.to_be_canceled
    assert dag.finished_tasks_status == {
        'failed': set(),
        'canceled': set(),
        'successful': set(),
    }
    assert dag.execution_plan == plan_dict
    build_dag_mock.assert_called_once()
    create_exec_plan_mock.assert_called_once_with(dep_dict)
    prepare_mock.assert_called_once()


@pytest.mark.parametrize('dag',
                         [{'reverse': True}, {'reverse': False}],
                         indirect=True)
@pytest.mark.parametrize('is_active', [True, False])
def test_dag_is_active(is_active: bool, dag: DAG):
    """Test DAG.is_active method.
    Check if dag.is_active method returns the value of the dag.dag.is_active() method.

    Parameters
    ----------
    is_active : bool
        Parametrized value returned by dag.dag.is_active
    dag : DAG
        DAG fixture defined in conftest.py.
    """
    with patch.object(dag.dag, 'is_active', return_value=is_active) as is_active_mock:
        assert dag.is_active() == is_active
    is_active_mock.assert_called_once()


@pytest.mark.parametrize('dag',
                         [{'execution_plan_dict': {'task1', 'task2'} }], indirect=True)
def test_get_execution_plan(dag: DAG):
    """Test DAG.get_execution_plan method.
    Check if the dag.get_execution_plan returns the dag.execution_plan instance

    Parameters
    ----------
    dag : DAG
        DAG fixture defined in conftest.py.
    """
    assert dag.get_execution_plan() == dag.execution_plan


@pytest.mark.parametrize('dag', [{}], indirect=True)
@pytest.mark.parametrize('task_name, status', [
    ('task1', 'failed'),
    ('task1', 'canceled'),
    ('task1', 'successful'),
])
def test_set_status(task_name:str, status:str, dag: DAG):
    """Test DAG.set_status method.
    Check if the dag.dag.done mode is properly called and that the task is in the failed, canceled or
    successful set.

    Parameters
    ----------
    task_name : str
        Parameterized value for the task name passed to  dag.set_status method.
    status : str
        Parameterized value for the task name passed to  dag.set_status method.
    dag : DAG
        DAG fixture defined in conftest.py.
    """
    with patch.object(dag.dag, "done") as done_mock:
        dag.set_status(task_name=task_name, status=status)
    assert task_name in dag.finished_tasks_status[status]
    done_mock.assert_called_once_with(task_name)


@pytest.mark.parametrize('dag', [{}], indirect=True)
@pytest.mark.parametrize('in_cancel', [True, False])
def test_should_be_canceled(in_cancel:bool, dag: DAG):
    """Test DAG.should_be_canceled method.
    Check if dag.should_be_canceled returns True or False if the task is in the dab.to_be_canceled set.

    Parameters
    ----------
    in_cancel : bool
        Parameterized value to test the method dag.should_be_canceled with 'task1' 
        in the dag.to_be_canceled set or not.
    dag : DAG
        DAG fixture defined in conftest.py.
    """
    if in_cancel:
        dag.to_be_canceled.add('task1')
    else:
        if 'task1' in dag.to_be_canceled:
            dag.to_be_canceled.remove('task1')

    assert dag.should_be_canceled(task_name='task1') == in_cancel


@pytest.mark.parametrize('dag',
                         [{
                             'task_collection': [
                                {'task': 'task1', },
                                {'task': 'task2', 'depends-on': ['task1']},
                                {'task': 'task3', 'depends-on': ['task1']},
                                {'task': 'task4', 'depends-on': ['task1']},
                                {'task': 'task5', 'depends-on': ['task2', 'task3', 'task4']}
                                ]
                           },
                            {'task_collection': [
                                {'task': 'task1', },
                                {'task': 'task2', 'depends-on': ['task1']},
                                {'task': 'task3', 'depends-on': ['task1']},
                                {'task': 'task4', 'depends-on': ['task1']},
                                {'task': 'task5', 'depends-on': ['task2', 'task3', 'task4']}],
                                'reverse': True
                            }
                         ],
                         indirect=True)
def test_build_dag(dag: DAG):
    """Test DAG.__build_dag method.
    The test uses a task collection and checks the calls to the graphlib.TopologicalSorter.add.
    The function calls depend on the dag.reverse instance variable, that it is also parameterized.

    Parameters
    ----------
    dag : DAG
        DAG fixture defined in conftest.py with task_collection parameterized.
    """
    with patch('jobflow.jobflow_processor.graphlib.TopologicalSorter.add') as mock_add:
        res_dag, res_dependency_dict = dag._DAG__build_dag()
    assert isinstance(res_dag, graphlib.TopologicalSorter)
    call_list = []
    dependency_dict = {}
    for task in dag.task_collection:
        dependencies = task.get('depends-on', [])
        task_name = task['task']
        if dag.reverse:
            for dependency in dependencies:
                call_list.append(call(dependency, task_name))
        else:
            call_list.append(call(task_name, *dependencies))
        dependency_dict[task_name] = dependencies

    assert res_dependency_dict == dependency_dict
    mock_add.assert_has_calls(call_list, any_order=True)


@pytest.mark.parametrize('dag',
                         [{
                             'task_collection': [
                                {'task': 'task1', },
                                {'task': 'task2', 'depends-on': ['task1']},
                                {'task': 'task3', 'depends-on': []},
                                {'task': 'task4', 'depends-on': []},
                                {'task': 'task5', 'depends-on': ['task2', 'task3', 'task4']}
                                ],
                                'patch': False
                           },
                            {'task_collection': [
                                {'task': 'task1', },
                                {'task': 'task2', 'depends-on': ['task1']},
                                {'task': 'task3', 'depends-on': []},
                                {'task': 'task4', 'depends-on': []},
                                {'task': 'task5', 'depends-on': ['task2', 'task3', 'task4']}],
                                'reverse': True,
                                'patch': False,
                                'finished_task_status': {
                                    'failed': set(),
                                    'canceled': set(),
                                    'successful': set()}
                            },
                         ],
                         indirect=True)
@pytest.mark.parametrize('task, cancel_policy, to_be_canceled',
                         [('task1', 'abort-all', {'task4', 'task3', 'task2', 'task5', 'task1'}),
                          ('task2', 'abort-all', {'task4', 'task3', 'task2', 'task5', 'task1'}),
                          ('task5', 'abort-all', {'task4', 'task3', 'task2', 'task5', 'task1'}),
                          ('task1', 'abort-related-flows', {'task4', 'task3', 'task2', 'task5', 'task1'}),
                          ('task2', 'abort-related-flows', {'task4', 'task3', 'task2', 'task5', 'task1'}),
                          ('task5', 'abort-related-flows', {'task4', 'task3', 'task2', 'task5', 'task1'}),
                          ('task1', 'continue', set()),
                          ('task2', 'continue', set()),
                          ('task5', 'continue', set()),
                          ])
def test_cancel_dependant_tasks(task: str, cancel_policy: str, to_be_canceled: set, dag: DAG):
    """Test DAG.cancel_dependant_tasks method.
    Check the to_be_canceled set after calling the cancel_dependant_tasks method with a parameterized task_collection
    in reverse True and False test cases.

    Parameters
    ----------
    task : str
        Parameterized task name.
    cancel_policy : str
        Parameterized cancel policy using valid values (abort-all, abort-related-flows, continue).
    to_be_canceled : set
        [description]
    dag : DAG
        DAG fixture defined in conftest.py parameterized with complete object state 
        (task_collection, reverse, finished_task_status sets). The patch false parameter avoids patching the 
        DAG.__build_dag' and DAG.__create_execution_plan methods
    """
    dag.cancel_dependant_tasks(task, cancel_policy=cancel_policy)
    assert dag.to_be_canceled == to_be_canceled


@pytest.mark.parametrize('dag, exec_plan',
                         [(
                             {'task_collection': [
                                    {'task': 'task1', },
                                    {'task': 'task2', 'depends-on': ['task1']},
                                    {'task': 'task3', 'depends-on': ['task1']},
                                    {'task': 'task4', 'depends-on': ['task1']},
                                    {'task': 'task5', 'depends-on': ['task2', 'task3', 'task4']}
                                ],
                                'patch': False},
                                {"task5": {"task2": {"task1": {}},
                                           "task3": {"task1": {}}, 
                                           "task4": {"task1": {}}}}
                           ),
                           (
                               {
                                   'task_collection': [
                                        {'task': 'task1', },
                                        {'task': 'task2', 'depends-on': ['task1']},
                                        {'task': 'task3', 'depends-on': ['task1']},
                                        {'task': 'task4', 'depends-on': ['task1']},
                                        {'task': 'task5', 'depends-on': ['task2', 'task3', 'task4']},
                                        {'task': 'task6', 'depends-on': ['task5']}
                                     ],
                                    'patch': False
                                },
                                {"task6": {"task5": {"task2": {"task1": {}},
                                                     "task3": {"task1": {}}, 
                                                     "task4": {"task1": {}}}}}
                           )
                         ],
                         indirect=['dag'])
def test_create_execution_plan(exec_plan: dict, dag: DAG):
    """Test DAG._create_execution_plan method.
    This private method is executed by the constructor. In this Test,
    the results are left in the execution_plan instance variable.

    Parameters
    ----------
    exec_plan : dict
        execution plan.
    dag : DAG
        DAG fixture defined in conftest.py.
    """
    assert dag.execution_plan == exec_plan
