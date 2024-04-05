# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
"""Unit Tests for the ProvisionHandler class."""
from unittest.mock import patch, MagicMock
import pytest

from modules.provision.handler import ProvisionHandler
from modules.provision.models import ComponentInfo

@pytest.mark.parametrize('component, action, method',
                         [('wazuh-manager', 'install', 'package'),
                          ('wazuh-manager', 'install', 'assistant'),
                          ('wazuh-manager', 'install', 'source'),
                          ('wazuh-manager', 'uninstall', 'package'),
                          ('wazuh-manager', 'uninstall', 'assistant'),
                          ('wazuh-manager', 'uninstall', 'source'),
                          ('wazuh-agent', 'uninstall', 'source'),
                          ('wazuh-agent', 'uninstall', 'assistant'),
])
@pytest.mark.parametrize('logger_mock',
                         [{'logger_to_patch': 'modules.provision.handler.logger'}],
                         indirect=True)
def test_provision_handler_constructor(component: str, action: str, method: str, logger_mock: MagicMock):
    """Test ProvisionHandler constructor.

    Parameters
    ----------
    component : str
        component type
    action : str
        valid values are install or uninstall
    method : str
        valid values are package, assistant, source
    logger_mock : MagicMock
        logger fixture defined en conftest.py
    """
    info = ComponentInfo(component=component, type='type', version='version', dependencies={})
    with patch('modules.provision.handler.ProvisionHandler._get_templates_path',
               return_value='path1'), \
         patch('modules.provision.handler.ProvisionHandler._get_templates_order',
                return_value=["set_repo.j2", "install.j2", "register.j2", "service.j2"]), \
         patch('modules.provision.handler.ProvisionHandler._generate_dict', return_value={'key':'value'}):
        handler = ProvisionHandler(component_info=info, action=action, method=method)

    if action == 'uninstall' and method == 'source':
        logger_mock.warning.assert_called_once_with("Uninstall from source not supported. Using package.")
        method = 'package'
    if 'wazuh-agent' in component and method == 'assistant':
        logger_mock.warning.assert_called_once_with("Agent can not be installed from assistant. Using package.")
        method = 'package'
    assert handler.component_info == info
    assert handler.action == action.lower()
    assert handler.method == method.lower()
    assert handler.templates_path == 'path1'
    assert handler.templates_order == ["set_repo.j2", "install.j2", "register.j2", "service.j2"]
    assert handler.variables_dict == {'key':'value'}


@pytest.mark.parametrize('component, action, method, to_match',
                         [('wazuh-manager', 'INSTALL', 'package', 'Unsupported action: INSTALL'),
                          ('wazuh-manager', 'UNINSTALL', 'assistant', 'Unsupported action: UNINSTALL'),
                          ('wazuh-manager', 'other', 'source', 'Unsupported action: other'),
                          ('wazuh-manager', 'uninstall', 'other', 'Unsupported method: other'),
                          ('indexer', 'uninstall', 'assistant',
                           "Assistant actions is only supported for Wazuh components."),
])
def test_provision_handler_constructor_fail(component: str, action: str, method: str, to_match: str):
    """Test ProvisionHandler constructor failure flows.

    Parameters
    ----------
    component : str
        component type
    action : str
        valid values are install or uninstall
    method : str
        valid values are package, assistant, source
    """
    info = ComponentInfo(component=component, version='version', dependencies={})
    # Use Package instead of ComponentType class because it is not posible to instantiate a class with
    # with abstract methods.
    with pytest.raises(ValueError, match=to_match):
        ProvisionHandler(component_info=info, action=action, method=method)


@pytest.mark.parametrize('component, method, action',
                         [('wazuh-manager', 'package', 'install'),
                          ('wazuh-manager', 'assistant', 'uninstall'),
                          ('indexer', 'source', 'install'),
])
def test_provision_handler_get_templates_path(component: str, method: str, action:str):
    """Test ProvisionHandler.get_templates_path method.

    Parameters
    ----------
    component : str
        component type
    action : str
        valid values are install or uninstall
    method : str
        valid values are package, assistant, source
    """
    info = ComponentInfo(component=component, version='version', dependencies={})
    with patch('modules.provision.handler.ProvisionHandler._get_templates_order',
            return_value=["set_repo.j2", "install.j2", "register.j2", "service.j2"]):
        handler = ProvisionHandler(component_info=info, action=action, method=method)
    assert handler.templates_path == f"{handler._base_templates_path}/{handler.method}/{handler.action}"


@pytest.mark.parametrize('component, method, action, expected_list',
                         [('wazuh-manager', 'package', 'install',
                           ["set_repo.j2", "install.j2", "register.j2", "service.j2"]),
                          ('indexer', 'source', 'install', ['indexer.j2']),
                          ('wazuh-manager', 'assistant', 'uninstall', []),
])
def test_provision_handler_get_templates_order(component: str, method: str, action:str, expected_list: list):
    """Test ProvisionHandler._get_templates_order method.

    Parameters
    ----------
    component : str
        component type
    action : str
        valid values are install or uninstall
    method : str
        valid values are package, assistant, source
    expected_list : list
        expected result
    """
    info = ComponentInfo(component=component, version='version', dependencies={})
    with patch('pathlib.Path.exists', return_value=True):
        handler = ProvisionHandler(component_info=info, action=action, method=method)
    assert handler.templates_order == expected_list


def test_provision_handler_get_templates_order_fail():
    """Test ProvisionHandler._get_templates_order method failure flow."""
    info = ComponentInfo(component='indexer', version='version', dependencies={})
    with pytest.raises(ValueError, match="Component source file indexer.j2 not found."):
        ProvisionHandler(component_info=info, action='install', method='source')


@pytest.mark.parametrize('component, method, action',
                         [('wazuh-manager', 'package', 'install'),
                          ('wazuh-manager', 'assistant', 'uninstall'),
                          ('indexer', 'source', 'install'),
])
def test_provision_handler_generate_dict(component: str, method: str, action:str):
    """Test ProvisionHandler._generate_dict method.

    Parameters
    ----------
    component : str
        component type
    method : str
        valid values are package, assistant, source
    action : str
        valid values are install or uninstall
    """
    info = ComponentInfo(component=component, version='version', dependencies={})
    with patch('pathlib.Path.exists', return_value=True):
        handler = ProvisionHandler(component_info=info, action=action, method=method)
    expected_dict = {
            'component': handler.component_info.component,
            'version': handler.component_info.version,
            'live': handler.component_info.live,
            'type': handler.component_info.type,
            'dependencies': handler.component_info.dependencies or None,
            'templates_path': handler.templates_path,
            'templates_order': handler.templates_order or None
        }
    assert handler.variables_dict == expected_dict
