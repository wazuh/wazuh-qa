# Copyright (C) 2015-2022, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import ansible_runner
import pytest
from tempfile import gettempdir

from wazuh_testing.tools.file import remove_file, get_file_lines


alerts_json = os.path.join(gettempdir(), 'alerts.json')
credentials_file = os.path.join(gettempdir(), 'passwords.wazuh')


@pytest.fixture(scope='function')
def clean_environment():
    """Delete alerts and credentials files from the temporary folder."""
    yield

    remove_file(alerts_json)
    remove_file(credentials_file)


@pytest.fixture(scope='module')
def get_dashboard_credentials():
    """Get wazuh-dashboard username and password.

       Returns:
            dict: wazuh-dashboard credentials.
    """
    password_index = None

    for index, line in enumerate(get_file_lines(credentials_file)):
        if 'username: admin' in line:
            user = line.split()[1]
            user_index = index
            password_index = user_index + 1
        if index == password_index:
            password = line.split()[1]

    dashboard_credentials = {'user': user, 'password': password}

    yield dashboard_credentials


@pytest.fixture(scope='module')
def configure_environment(request, pytestconfig):
    """Fixture to configure environment.

    Execute the configuration playbooks declared in the test to configure the environment.

    Args:
        request (fixture): Provide information on the executing test function.
    """
    metadata = getattr(request.module, 'configuration_metadata')
    inventory_playbook = pytestconfig.getoption('--inventory_path')

    if not inventory_playbook:
        raise ValueError('No specified inventory')

    for playbook in getattr(request.module, 'configuration_playbooks'):
        configuration_playbook_path = os.path.join(getattr(request.module, 'test_data_path'), 'playbooks', playbook)

    for test_case in metadata:
        if 'extra_vars' in test_case:
            ansible_runner.run(playbook=configuration_playbook_path, inventory=inventory_playbook,
                               extravars=test_case['extra_vars'])
        else:
            ansible_runner.run(playbook=configuration_playbook_path, inventory=inventory_playbook)


@pytest.fixture(scope='function')
def generate_events(request, metadata, pytestconfig):
    """Fixture to generate events.

    Execute the playbooks declared in the test to generate events.
    Args:
        request (fixture): Provide information on the executing test function.
    """
    inventory_playbook = pytestconfig.getoption('--inventory_path')

    if not inventory_playbook:
        raise ValueError('No specified inventory')

    for playbook in getattr(request.module, 'events_playbooks'):
        generate_events_playbook_path = os.path.join(getattr(request.module, 'test_data_path'), 'playbooks', playbook)

    if 'extra_vars' in metadata:
        ansible_runner.run(playbook=generate_events_playbook_path, inventory=inventory_playbook,
                           extravars=metadata['extra_vars'])
    else:
        ansible_runner.run(playbook=generate_events_playbook_path, inventory=inventory_playbook)


def pytest_addoption(parser):
    parser.addoption(
        '--inventory_path',
        action='store',
        metavar='INVENTORY_PATH',
        default=None,
        type=str,
        help='Inventory path',
    )
