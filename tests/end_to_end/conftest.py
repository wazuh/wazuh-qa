# Copyright (C) 2015-2022, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import pytest
from tempfile import gettempdir
from pytest_ansible_playbook import runner

from wazuh_testing.tools.file import remove_file, get_file_lines


alerts_json = os.path.join(gettempdir(), 'alerts.json')
credentials_file = os.path.join(gettempdir(), 'passwords.wazuh')


@pytest.fixture(scope='function')
def clean_environment():
    """Delete alerts and credentials files from the temporary folder."""
    yield

    remove_file(alerts_json)
    remove_file(credentials_file)


@pytest.fixture(scope='function')
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

    dashboard_credentials = {'user': users_list[0], 'password': passwords_list[0]}

    yield dashboard_credentials


@pytest.fixture(scope='module')
def configure_environment(request):
    """Fixture to configure environment.

    Execute the configuration playbooks declared in the test to configure the environment.

    Args:
        request (fixture): Provide information on the executing test function.
    """
    configuration_playbooks = getattr(request.module, 'configuration_playbooks')
    with runner(request, configuration_playbooks):

        yield


@pytest.fixture(scope='function')
def generate_events(request):
    """Fixture to generate events.

    Execute the playbooks declared in the test to generate events.
    Args:
        request (fixture): Provide information on the executing test function.
    """
    events_playbooks = getattr(request.module, 'events_playbooks')
    with runner(request, events_playbooks):

        yield
