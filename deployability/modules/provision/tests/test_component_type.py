# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
"""Unit Tests for the ComponentType class and inherited classes."""


from unittest.mock import patch
import pytest

from modules.provision.component_type import AIO, Generic, ComponentInfo, Package, Dependencies


@pytest.mark.parametrize('dependencies, res_dep',
                         [({}, None),
                          (None, None),
                          ({"dep_1": 'a', "dep_2": 'b'},{"dep_1": 'a', "dep_2": 'b'})]
)
def test_component_type_constructor(dependencies, res_dep):
    """Test ComponentType constructor."""
    info = ComponentInfo(component='component', type='type', version='version', dependencies=dependencies)
    # Use Package instead of ComponentType class because it is not posible to instantiate a class with
    # with abstract methods.
    component = Package(component_info=info, action='action')
    assert component.component == info.component
    assert component.type == info.type
    assert component.version == info.version
    assert component.dependencies == res_dep


def test_package_constructor():
    """Test Package constructor."""
    action = 'action'
    info = ComponentInfo(component='component', type='type', version='version', dependencies={})
    with patch('modules.provision.component_type.Package.get_templates_order') as order_mock, \
         patch('modules.provision.component_type.ComponentType.generate_dict') as gen_dict_mock:
        component = Package(component_info=info, action=action)
    assert component.templates_path == f'{Package._Package__TEMPLATE_BASE_PATH}/{component.type}/{action}'
    order_mock.assert_called_once_with(action)
    gen_dict_mock.assert_called_once()


@pytest.mark.parametrize('action, expected_template_list',
                         [('action', []),
                          ('install', ["set_repo.j2", "install.j2", "register.j2", "service.j2"])])
def test_package_get_templates_order(action: str, expected_template_list: list):
    """Test AIO.get_template_order method."""
    info = ComponentInfo(component='component', type='type', version='version', dependencies={})
    component = Package(component_info=info, action=action)
    template_list = component.get_templates_order(action=action)
    assert template_list == expected_template_list


def test_aio_constructor():
    """Test AIO constructor."""
    action = 'action'
    info = ComponentInfo(component='component', type='type', version='version', dependencies={})
    with patch('modules.provision.component_type.AIO.get_templates_order') as order_mock, \
         patch('modules.provision.component_type.ComponentType.generate_dict') as gen_dict_mock:
        component = AIO(component_info=info, action=action)
    assert component.templates_path == f'{AIO._AIO__TEMPLATE_BASE_PATH}/{component.type}/{action}'
    order_mock.assert_called_once_with(action)
    gen_dict_mock.assert_called_once()


def test_aio_get_templates_order():
    """Test AIO.get_template_order method."""
    action = 'action'
    info = ComponentInfo(component='component', type='type', version='version', dependencies={})
    component = AIO(component_info=info, action=action)
    template_list = component.get_templates_order(action=action)
    assert template_list == ["download.j2", f"{action}.j2"]


def test_generic_constructor():
    """Test Generic constructor."""
    action = 'action'
    info = ComponentInfo(component='component', type='type', version='version', dependencies={})
    with patch('modules.provision.component_type.Generic.get_templates_order') as order_mock, \
         patch('modules.provision.component_type.ComponentType.generate_dict') as gen_dict_mock:
        component = Generic(component_info=info, action=action)
    component.templates_path = f'{Generic._Generic__TEMPLATE_BASE_PATH}/{action}'
    order_mock.assert_called_once_with(action)
    gen_dict_mock.assert_called_once()


def test_generic_get_templates_order():
    """Test Generic.get_template_order method."""
    action = 'action'
    info = ComponentInfo(component='component', type='type', version='version', dependencies={})
    component = Generic(component_info=info, action=action)
    template_list = component.get_templates_order(action=action)
    assert isinstance(template_list, list) and not template_list


def test_dependencies_constructor():
    """Test Generic constructor."""
    action = 'action'
    info = ComponentInfo(component='component', type='type', version='version', dependencies={})
    with patch('modules.provision.component_type.Dependencies.get_templates_order') as order_mock, \
         patch('modules.provision.component_type.ComponentType.generate_dict') as gen_dict_mock:
        component = Dependencies(component_info=info, action=action)
    component.templates_path = f'{Dependencies._Dependencies__TEMPLATE_BASE_PATH}'
    order_mock.assert_called_once_with(action)
    gen_dict_mock.assert_called_once()


def test_dependencies_get_templates_order():
    """Test Generic.get_template_order method."""
    action = 'action'
    info = ComponentInfo(component='component', type='type', version='version', dependencies={})
    component = Dependencies(component_info=info, action=action)
    template_list = component.get_templates_order(action=action)
    assert isinstance(template_list, list) and not template_list
