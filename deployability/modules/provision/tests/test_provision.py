# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
"""Unit Tests for the Provision class"""

from typing import List
from unittest.mock import patch, MagicMock, call
import pytest

from modules.provision.models import InputPayload, ComponentInfo
from modules.provision.provision import Provision


def test_provision_constructor():
    """Test Provision constructor."""
    component_info = "{'component':'component', 'type':'component_type'}"
    payload = InputPayload(inventory="path", dependencies={}, install=[component_info], uninstall=[component_info])
    with patch('modules.provision.provision.Provision.get_components') as get_comp_mock, \
         patch('modules.provision.provision.Provision._Provision__load_ansible_data') as load_ansible_mock:
        prov = Provision(payload=payload)
    assert len(prov.summary) == 0
    get_comp_mock.assert_called_once_with(payload)
    load_ansible_mock.assert_called_once_with(payload.inventory)


@pytest.mark.parametrize('logger_mock, provision_mock, stats',
                         [(
                             {'logger_to_patch': 'modules.provision.provision.logger'},
                             {'components': [
                               ComponentInfo(component='component_1', type='type_1'),
                               ComponentInfo(component='component_2', type='type_2')]},
                               {'component_1': {'stat_component_1': 'status component_1'},
                                'component_2': {'stat_component_2': 'status component_2'}})
                         ],
                         indirect=['logger_mock', 'provision_mock'])
def test_provision_run(logger_mock: MagicMock, provision_mock: Provision, stats: List[dict]):
    """Test Provision.run method.

    Parameters
    ----------
    logger_mock : MagicMock
        logger fixture defined in conftest.py.
    provision_mock : Provision
        provision fixture defined in conftest.py
    stats : List[dict]
        keys to update mocking the __provision method
    """
    with patch.object(provision_mock, '_Provision__provision',
                      side_effect=lambda c: provision_mock.summary.update(stats[c.component])) as provision_method_mock:
        provision_mock.run()

    assert provision_method_mock.call_count == 2
    logger_mock.info.assert_has_calls([
        call('Initiating provisionment.'),
        call('Provisioning "component_1"...'),
        call('Provision of "component_1" complete successfully.'),
        call('Provisioning "component_2"...'),
        call('Provision of "component_2" complete successfully.'),
        call('All components provisioned successfully.')
    ])
    logger_mock.debug.assert_has_calls([
        call(f'Running action {provision_mock.action} for components: {provision_mock.components}'),
        call(f'Provision summary: {provision_mock.summary}')
    ])


@pytest.mark.parametrize('logger_mock, provision_mock',
                         [(
                             {'logger_to_patch': 'modules.provision.provision.logger'},
                             {'components': [
                               ComponentInfo(component='component_1', type='type_1'),
                               ComponentInfo(component='component_2', type='type_2')]})
                         ],
                         indirect=['logger_mock', 'provision_mock'])
def test_provision_run_fail(logger_mock: MagicMock, provision_mock: Provision):
    """Test Provision.run method failure flow.

    Parameters
    ----------
    logger_mock : MagicMock
        logger fixture defined in conftest.py.
    provision_mock : Provision
        provision fixture defined in conftest.py
    """

    with patch.object(provision_mock, '_Provision__provision',
                      side_effect=[None, Exception('Provision generated Exception')]):
        with pytest.raises(Exception) as exc_info:
            provision_mock.run()

    assert logger_mock.info.call_count == 4
    logger_mock.error.assert_called_once_with(f'Error while provisioning "component_2": {exc_info.value}')


@pytest.mark.parametrize('provision_mock, install',[({}, True), ({}, False)], indirect=['provision_mock'])
def test_provision_get_components(provision_mock: Provision, install: bool):
    """Test Provision.get_component method.

    Parameters
    ----------
    provision_mock : Provision
        provision fixture defined in conftest.py.
    install : bool
        parameterization of the InputPayload constructor install and uninstall parameters
    """
    component_info = ["{'component':'component_1', 'type':'component_type_1'}",
                       "{'component':'component_2', 'type':'component_type_2'}"]
    if install:
        payload = InputPayload(inventory="path", dependencies={}, install=component_info, uninstall=[])
    else:
        payload = InputPayload(inventory="path", dependencies={}, install=[], uninstall=component_info)
    with patch.object(provision_mock, '_Provision__get_deps_ips') as get_deps_mock, \
         patch.object(provision_mock, '_Provision__validate_component_deps') as validate_mock:
        provision_mock.get_components(payload=payload)
    get_deps_mock.assert_called_once_with(payload.dependencies)
    assert validate_mock.call_count == 2


@pytest.mark.parametrize('provision_mock', [{}], indirect=['provision_mock'])
def test_provision_update_status(provision_mock: Provision):
    """Test Provision.update_status method.

    Parameters
    ----------
    provision_mock : Provision
        provision fixture defined in conftest.py.
    """
    status = MagicMock()
    status.stats = {'status_1': 'status 1', 'status_2': 'status 2'}
    provision_mock.update_status(status)
    assert provision_mock.summary == status.stats


@pytest.mark.parametrize('provision_mock', [{}], indirect=['provision_mock'])
def test_provision_provision(provision_mock: Provision):
    """Test Provision.__provision method.

    Parameters
    ----------
    provision_mock : Provision
        provision fixture defined in conftest.py.
    """
    component = MagicMock()
    status = MagicMock()
    action = MagicMock()
    action.execute.return_value = status
    with patch('modules.provision.provision.Action', return_value=action) as action_mock, \
         patch.object(provision_mock, 'update_status') as update_mock:
        provision_mock._Provision__provision(component=component)
    action_mock.assert_called_once_with(provision_mock.action, component, provision_mock.ansible_data)
    action.execute.assert_called_once()
    update_mock.assert_called_once_with(status)


@pytest.mark.parametrize('provision_mock', [{}], indirect=['provision_mock'])
def test_provision_load_ansible_data(provision_mock: Provision):
    """Test Provision.__load_ansible_data method.

    Parameters
    ----------
    provision_mock : Provision
        provision fixture defined in conftest.py.
    """
    inventory = '/inventory_path'
    with patch('modules.provision.provision.Utils.load_from_yaml') as load_yaml_mock:
        provision_mock._Provision__load_ansible_data(inventory)
    load_yaml_mock.assert_called_once_with(inventory)


@pytest.mark.parametrize('logger_mock, provision_mock, exc',
                         [({'logger_to_patch': 'modules.provision.provision.logger'}, {},
                           Exception),
                          ({'logger_to_patch': 'modules.provision.provision.logger'}, {},
                           FileNotFoundError)],
                         indirect=['logger_mock', 'provision_mock'])
def test_provision_load_ansible_data_fail(logger_mock: MagicMock, provision_mock: Provision, exc: Exception):
    """Test Provision.__load_ansible_data method failure flow.

    Parameters
    ----------
    logger_mock : MagicMock
        logger fixture defined in conftest.py.
    provision_mock : Provision
        provision fixture defined in conftest.py.
    exc : Exception
        expected exception
    """
    inventory = '/inventory_path'
    with pytest.raises(exc) as exc_info:
        with patch('modules.provision.provision.Utils.load_from_yaml', side_effect=exc) as load_yaml_mock:
            provision_mock._Provision__load_ansible_data(inventory)
    if isinstance(exc_info.value, FileNotFoundError):
        logger_mock.error.assert_called_once_with(f'Inventory file "{inventory}" not found.')
    else:
        logger_mock.error.assert_called_once_with(f'Error loading inventory file "{inventory}": {exc_info.value}')


@pytest.mark.parametrize('provision_mock, empty', [({}, True), ({}, False)], indirect=['provision_mock'])
def test_provision_get_deps_ips(provision_mock: Provision, empty: bool):
    """Test Provision.__get_deps_ips method.

    Parameters
    ----------
    provision_mock : Provision
        provision fixture defined in conftest.py.
    empty : bool
        dependencies are empty is True else dependecies are defined.
    """
    dependencies = {}
    paths = []
    if not empty:
        dependencies = {'dependency_1': '/path_1', 'dependency_2': '/path_2'}
        m1 = MagicMock()
        m1.exists.return_value = True
        m2 = MagicMock()
        m2.exists.return_value = True
        paths = [m1, m2]
    with patch('modules.provision.provision.Utils.load_from_yaml', side_effect=paths) as load_yaml_mock, \
         patch('modules.provision.provision.Path', side_effect=paths) as path_mock:
        dependencies_ips = provision_mock._Provision__get_deps_ips(dependencies)
    if empty:
        assert not dependencies
    else:
        load_yaml_mock.assert_has_calls([call(m1, specific_key='ansible_host'),
                                         call(m2, specific_key='ansible_host'),])
        path_mock.assert_has_calls([call(dependencies['dependency_1']),
                                    call(dependencies['dependency_2'])])
        assert dependencies_ips == {'dependency_1': m1, 'dependency_2': m2}


@pytest.mark.parametrize('logger_mock, provision_mock',
                         [({'logger_to_patch': 'modules.provision.provision.logger'}, {})],
                          indirect=['provision_mock', 'logger_mock'])
def test_provision_get_deps_ips_fail(logger_mock: MagicMock, provision_mock: Provision):
    """Test Provision.__get_deps_ips method failure flow.

    Parameters
    ----------
    logger_mock : MagicMock
        logger fixture defined in conftest.py.
    provision_mock : Provision
        provision fixture defined in conftest.py.
    """
    dependencies = {'dependency_1': '/path_1', 'dependency_2': '/path_2'}
    m1 = MagicMock()
    m1.exists.return_value = False
    m1.__str__.return_value = "/path_1"
    with pytest.raises(FileNotFoundError, match=f'Inventory file "{m1}" not found.') as exc_info, \
         patch('modules.provision.provision.Path', return_value=m1):
        provision_mock._Provision__get_deps_ips(dependencies)
    logger_mock.error.assert_called_once_with(f'Error getting dependency IP: {exc_info.value}')


@pytest.mark.parametrize('logger_mock, provision_mock, component_name, dependencies',
                         [({'logger_to_patch': 'modules.provision.provision.logger'}, {},
                           'wazuh-agent', {'manager': 'wazuh-manager'}),
                           ({'logger_to_patch': 'modules.provision.provision.logger'}, {},
                           'wazuh-manager', {'other': 'other'})],
                          indirect=['provision_mock', 'logger_mock'])
def test_provision_validate_component_deps(logger_mock: MagicMock, provision_mock: Provision, component_name: str,
                                           dependencies: dict):
    """Test Provision.__validate_component_deps method.

    Parameters
    ----------
    logger_mock : MagicMock
        logger fixture defined in conftest.py.
    provision_mock : Provision
        provision fixture defined in conftest.py.
    component_name : str
        componente name.
    dependencies : dict
        ComponentInfo dependencies parameter.
    """
    component = ComponentInfo(component=component_name, type='type_1', dependencies=dependencies)
    provision_mock._Provision__validate_component_deps(component)
    logger_mock.debug.assert_called_once_with(
        f"Setting dependencies: {dependencies} for {component.component} component.")



@pytest.mark.parametrize('provision_mock', [({})],
                          indirect=['provision_mock'])
def test_provision_validate_component_deps_fail(provision_mock: Provision):
    """Test Provision.__validate_component_deps method failure flow.

    Parameters
    ----------
    provision_mock : Provision
        provision fixture defined in conftest.py.
    """
    component = ComponentInfo(component='wazuh-agent', type='type_1', dependencies={'other': 'other'})
    with pytest.raises(ValueError, match='Dependency IP is required to install Wazuh Agent.'):
        provision_mock._Provision__validate_component_deps(component)
