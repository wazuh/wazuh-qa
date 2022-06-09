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
    password = ''
    user = ''

    for line in get_file_lines(credentials_file):
        if 'username: admin' in line:
            user = 'admin'

        if 'password: ' in line and user == 'admin':
            password_line = line
            password = password_line.split()[1]

        if user != '' and password != '':
            break

    dashboard_credentials = {'user': user, 'password': password}

    yield dashboard_credentials


@pytest.fixture(scope="module")
def run_ansible_playbooks(request):
    """Will run a list of playbooks defined in the 'playbooks' attribute of the executing test function.
    
    The 'playbooks' attribute is a python dictionary with the following structure:
    {
        'setup_playbooks': (list),
        'teardown_playbooks': (list),
        'skip_teardown': (bool)
    }

    Args:
        request (fixture): Provide information on the executing test function.
    """
    # Check if the required attributes are defined.
    try:
        params = request.module.playbooks
    except AttributeError as e:
        print(e)

    with runner(request, params['setup_playbooks'], params['teardown_playbooks'], params['skip_teardown']):

        yield


@pytest.fixture(scope="function")
def run_extra_playbooks(request):
    """Will run a list of playbooks if an element called 'extra_playbooks' exists in the metadata list inside the test
    case YAML file.

    The 'extra_playbooks' is a list of playbook files. Example: ['run_commands.yaml', 'configure_wodle.yaml']

    Args:
        request (fixture): Provide information on the executing test function.
    """
    extra_playbooks = None
    # Get the current test case id
    current_test_case_id = request.node.name.split('[')[1].replace(']', '')

    # Each 'case' has the metadata object of the test case
    for case in request.module.configuration_metadata:
        # Check if the current test case has extra playbooks to run
        if case['name'] == current_test_case_id:
            try:
                extra_playbooks = case['extra_playbooks']
            except KeyError as e:
                pass

    with runner(request, setup_playbooks=extra_playbooks, skip_teardown=True):

        yield
