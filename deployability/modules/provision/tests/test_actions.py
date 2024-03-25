# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
"""Unit Tests for the Action class"""

from unittest.mock import patch, MagicMock
import pytest

from modules.generic import Ansible
from modules.provision.actions import Action
from modules.provision.models import ComponentInfo
from modules.provision.component_type import Package, AIO, Generic, Dependencies, ComponentType


@pytest.mark.parametrize('action, component_type, cls',
                         [('action1', 'package', Package),
                          ('action1', 'aio', AIO),
                          ('action1', 'generic', Generic),
                          ('action1', 'dependencies', Dependencies)])
def test_action_constructor(action: str, component_type: str, cls: ComponentType):
    """Test Action constructor."""
    component_info = ComponentInfo(component='myComponent', type=component_type)
    ansible_data =  {'ansible_host': '', 'ansible_user': '', 'ansible_port': 0, 'ansible_ssh_private_key_file': ''}
    action : Action = Action(action=action, component_info=component_info, ansible_data=ansible_data)
    assert isinstance(action.component, cls)
    assert isinstance(action.ansible, Ansible)


def test_action_constructor_fail():
    """Test Action constructor fail."""
    invalid_component = 'invalid_component'
    component_info = ComponentInfo(component='myComponent', type=invalid_component)
    ansible_data =  {'ansible_host': '', 'ansible_user': '', 'ansible_port': 0, 'ansible_ssh_private_key_file': ''}
    with pytest.raises(ValueError, match=f"Unsupported action_type: {invalid_component}"):
        Action(action='action', component_info=component_info, ansible_data=ansible_data)


@pytest.mark.parametrize('logger_mock', 
                         [{'logger_to_patch': 'modules.provision.actions.logger'}], indirect=True)
def test_action_execute(logger_mock: MagicMock):
    """Test Action.run method."""
    run_playbook_call_args = []
    def run_playbook_side_effect(dict_parm: dict) -> MagicMock:
        """Side effect to compare function calls arguments. A regular assert_has_calls
           does not work because the dictionary is passed by reference to the Ansible.run_playbook
           inside Action.execute."""
        run_playbook_call_args.append(dict_parm.copy())
        mock = MagicMock()
        mock.get_fact_cache.return_value = {'ansible_os_family': ansible_os_family}
        return mock

    ansible_host = 'myHost'
    ansible_os_family = 'os_family'
    return_tasks = ['task1', 'task2']

    ansible_task = [{
        'name': 'Capture ansible_os_family',
        'set_fact': {
            'ansible_os_family': "{{ ansible_facts['distribution_file_variety'] }}",
            'cacheable': 'yes'
        }
    }]

    playbook_1 = {
        'hosts': ansible_host,
        'become': True,
        'gather_facts': True,
        'tasks': ansible_task
    }
    playbook_2 = playbook_1.copy()
    playbook_2['tasks'] = return_tasks

    component_info = ComponentInfo(component='myComponent', type='package')
    ansible_data =  {'ansible_host': ansible_host, 'ansible_user': '',
                     'ansible_port': 0, 'ansible_ssh_private_key_file': ''}

    action : Action = Action(action='myAction', component_info=component_info, ansible_data=ansible_data)
    with patch.object(action.ansible, 'render_playbooks', return_value=return_tasks) as render_mock, \
         patch.object(action.ansible, 'run_playbook', side_effect=run_playbook_side_effect):
        action.execute()

    render_mock.assert_called_once_with(action.component.variables_dict)
    assert action.component.variables_dict['ansible_os_family'] == ansible_os_family
    assert [playbook_1, playbook_2] == run_playbook_call_args
    logger_mock.info.assert_called_once_with(f"Executing {action.component.type} for {action.component.component}")
