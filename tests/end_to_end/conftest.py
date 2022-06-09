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
    passwords_list = []
    users_list = []

    for line in get_file_lines(credentials_file):
        if 'username:' in line:
            user = line.split()[1]
            users_list.append(user)

        if 'password:' in line:
            password = line.split()[1]
            passwords_list.append(password)

    if len(users_list) == 0 or len(passwords_list) == 0:
        raise ValueError('No credentials found')

    dashboard_credentials = {'user': users_list[0], 'password': passwords_list[0]}

    yield dashboard_credentials


@pytest.fixture(scope='module')
def configure_environment(request):
    """Fixture to configure environment.

    Execute the configuration playbooks declared in the test to configure the environment.

    Args:
        request (fixture): Provide information on the executing test function.
    """
    inventory_playbook = request.config.getoption('--inventory_path')

    if not inventory_playbook:
        raise ValueError('Inventory not specified')

    for playbook in getattr(request.module, 'configuration_playbooks'):
        configuration_playbook_path = os.path.join(getattr(request.module, 'test_data_path'), 'playbooks', playbook)
        ansible_runner.run(playbook=configuration_playbook_path, inventory=inventory_playbook)


@pytest.fixture(scope='function')
def generate_events(request, metadata):
    """Fixture to generate events.

    Execute the playbooks declared in the test to generate events.
    Args:
        request (fixture): Provide information on the executing test function.
        metadata (dict): Dictionary with test case metadata.
    """
    inventory_playbook = request.config.getoption('--inventory_path')

    if not inventory_playbook:
        raise ValueError('Inventory not specified')

    for playbook in getattr(request.module, 'events_playbooks'):
        events_playbook_path = os.path.join(getattr(request.module, 'test_data_path'), 'playbooks', playbook)

        parameters = {'playbook': events_playbook_path, 'inventory': inventory_playbook}
        if 'extra_vars' in metadata:
            parameters.update({'extravars': metadata['extra_vars']})

        ansible_runner.run(**parameters)


def pytest_addoption(parser):
    parser.addoption(
        '--inventory_path',
        action='store',
        metavar='INVENTORY_PATH',
        default=None,
        type=str,
        help='Inventory path',
    )
