# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
"""Common unit test fixtures."""
from unittest.mock import patch
import pytest

from modules.provision.models import InputPayload
from modules.provision.provision import Provision


@pytest.fixture
def logger_mock(request):
    """Fixture to mock common logger methods."""
    logger_to_patch = request.param.get('logger_to_patch', "modules.provision.utils.logger")
    with patch(logger_to_patch) as l_mock:
        patch.object(l_mock, 'warning')
        patch.object(l_mock, 'info')
        patch.object(l_mock, 'debug')
        patch.object(l_mock, 'error')
        yield l_mock


@pytest.fixture
def provision_mock(request) -> Provision:
    """Fixture to create Provision class instances."""
    components = request.param.get('components', [])
    action = request.param.get('action', 'install')
    ansible_data = request.param.get('action', {})
    dependencies = request.param.get('dependencies', {})

    component_info = "{'component':'component', 'type':'component_type'}"
    payload = InputPayload(inventory="path", dependencies=dependencies,
                           install=[component_info], uninstall=[component_info])
    with patch('modules.provision.provision.Provision.get_components'), \
         patch('modules.provision.provision.Provision._Provision__load_ansible_data'):
        provision = Provision(payload)
        provision.components = components
        provision.action = action
        provision.ansible_data = ansible_data

    return provision
