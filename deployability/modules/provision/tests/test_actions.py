# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
"""Unit Tests for the Action class"""

from unittest.mock import patch, MagicMock, call
import pytest

from modules.generic import Ansible
from modules.provision.actions import Action
from modules.provision.models import ComponentInfo
from modules.provision.handler import ProvisionHandler


@pytest.mark.parametrize('action, component_type',
                         [('install', 'package'),
                          ('install', 'package'),
                          ('install', 'source')])
def test_action_constructor(action: str, component_type: str):
    """Test Action constructor.

    Parameters
    ----------
    component : str
        component type
    action : str
        valid values are install or uninstall
    """
    component_info = ComponentInfo(component='myComponent', type=component_type)
    ansible_data =  {'ansible_host': '', 'ansible_user': '', 'ansible_port': 0, 'ansible_ssh_private_key_file': ''}
    with patch('pathlib.Path.exists', return_value=True):
        action : Action = Action(action=action, component_info=component_info, ansible_data=ansible_data)
    assert isinstance(action.handler, ProvisionHandler)
    assert isinstance(action.ansible, Ansible)



@pytest.mark.parametrize('logger_mock',
                         [{'logger_to_patch': 'modules.provision.actions.logger'}], indirect=True)
def test_action_execute(logger_mock: MagicMock):
    """Test Action.run method.

    Parameters
    ----------
    logger_mock : MagicMock
        logger fixture defined in conftest.py
    """
    ansible_host = 'myHost'
    return_tasks = ['task1', 'task2']

    ansible_task = [{
        'name': 'Capture ansible_os_family',
        'set_fact': {
            'ansible_os_family': "{{ ansible_facts['distribution_file_variety'] }}",
            'cacheable': 'yes'
        }
    }]

    playbook = {
        'hosts': ansible_host,
        'become': True,
        'gather_facts': True,
        'tasks': ansible_task
    }
    status_mock = MagicMock()
    component_info = ComponentInfo(component='myComponent', type='package')
    ansible_data =  {'ansible_host': ansible_host, 'ansible_user': '',
                     'ansible_port': 0, 'ansible_ssh_private_key_file': ''}

    action : Action = Action(action='install', component_info=component_info, ansible_data=ansible_data)
    with patch('modules.provision.actions.Action._get_playbook', return_value=playbook) as get_playbook_mock, \
         patch.object(action.ansible, 'render_playbooks', return_value=return_tasks) as render_mock, \
         patch.object(action.ansible, 'run_playbook', return_value=status_mock) as run_playbook_mock, \
         patch('modules.provision.actions.Action._get_os_family', return_value='linux') as get_os_mock:
        result = action.execute()

    get_playbook_mock.assert_called_once_with(return_tasks)
    get_os_mock.assert_called_once()
    render_mock.assert_called_once_with(action.handler.variables_dict)
    run_playbook_mock.assert_called_once_with(playbook)
    assert result == status_mock
    logger_mock.debug.assert_has_calls([
        call(f"Render playbook with vars: {action.handler.variables_dict}."),
        call(f"Tasks to execute: {return_tasks}.")
    ])
    logger_mock.info.assert_called_once_with(
        f"Execute {action.handler.action} for {action.handler.component_info.component}.")


@pytest.mark.parametrize('logger_mock',
                         [{'logger_to_patch': 'modules.provision.actions.logger'}], indirect=True)
def test_action_get_os_family(logger_mock: MagicMock):
    """Test Action._get_os_falily method.

    Parameters
    ----------
    logger_mock : MagicMock
        logger fixture defined in conftest.py
    """
    ansible_host = 'myHost'
    ansible_task = [{
        'name': 'Capture ansible_os_family',
        'set_fact': {
            'ansible_os_family': "{{ ansible_facts['distribution_file_variety'] }}",
            'cacheable': 'yes'
        }
    }]

    playbook = {
        'hosts': ansible_host,
        'become': True,
        'gather_facts': True,
        'tasks': ansible_task
    }
    fact_cache_mock = MagicMock()
    fact_cache_mock.get.return_value = 'os_family'
    status_mock = MagicMock()
    status_mock.get_fact_cache.return_value = fact_cache_mock

    component_info = ComponentInfo(component='myComponent', type='package')
    ansible_data =  {'ansible_host': ansible_host, 'ansible_user': '',
                     'ansible_port': 0, 'ansible_ssh_private_key_file': ''}

    action : Action = Action(action='install', component_info=component_info, ansible_data=ansible_data)
    with patch('modules.provision.actions.Action._get_playbook', return_value=playbook) as get_playbook_mock, \
         patch.object(action.ansible, 'run_playbook', return_value=status_mock) as run_playbook_mock:
        result = action._get_os_family()

    get_playbook_mock.assert_called_once_with(ansible_task)
    run_playbook_mock.assert_called_once_with(playbook)
    status_mock.get_fact_cache.assert_called_once_with(host=action.ansible.ansible_data.ansible_host)
    fact_cache_mock.get.assert_has_calls([call('ansible_os_family'), call('ansible_os_family')])

    assert result == 'os_family'
    logger_mock.debug.assert_has_calls([
        call(f"Get OS family for {action.ansible.ansible_data.ansible_host}."),
        call("OS family: os_family.")
    ])


def test_provision_handler_get_playbook():
    """Test ProvisionHandler._get_playbook method."""
    tasks = ['task1', 'task2']
    component_info = ComponentInfo(component='myComponent', type='package')
    ansible_data =  {'ansible_host': 'ansible_host', 'ansible_user': '',
                     'ansible_port': 0, 'ansible_ssh_private_key_file': ''}
    action = Action(action='install', component_info=component_info, ansible_data=ansible_data)
    result = action._get_playbook(tasks=tasks)
    playbook = {
        'hosts': action.ansible.ansible_data.ansible_host,
        'become': True,
        'gather_facts': True,
        'tasks': tasks,
    }
    assert result == playbook
