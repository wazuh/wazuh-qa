'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: Whenever a file is created or deleted from the group directory the merged.mg file must be updated. This test
       checks the content of the merged.mg file that wazuh-remoted compiles for multi-groups.

tier: 0

modules:
    - remoted

components:
    - manager

daemons:
    - wazuh-remoted

os_platform:
    - linux

os_version:
    - Arch Linux
    - Amazon Linux 2
    - Amazon Linux 1
    - CentOS 8
    - CentOS 7
    - Debian Buster
    - Red Hat 8
    - Ubuntu Focal
    - Ubuntu Bionic

references:
    - https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-remoted.html

tags:
    - remoted
'''
import hashlib
import os
import re
import subprocess as sb
from time import sleep

import pytest
import requests
from wazuh_testing.api import get_api_details_dict
from wazuh_testing.remote import DEFAULT_TESTING_GROUP_NAME, new_agent_group, \
                                  remove_agent_group
from wazuh_testing.tools import REMOTE_DAEMON, WAZUH_PATH, configuration
from wazuh_testing.tools.file import delete_file
import wazuh_testing.tools as tools
from wazuh_testing.tools.services import check_daemon_status, control_service
from wazuh_testing.tools.wazuh_manager import remove_agents

# Marks
pytestmarks = [pytest.mark.linux, pytest.mark.server, pytest.mark.tier(level=0)]

# Variables
agent_name = 'testing_agent'
agent_ip = 'any'
groups_folder = os.path.join(WAZUH_PATH, 'queue', 'agent-groups')
default_group_name = 'default'
groups_list = [default_group_name, DEFAULT_TESTING_GROUP_NAME]
mg_name = hashlib.sha256(','.join(groups_list).encode()).hexdigest()[:8]
mg_folder_path = os.path.join(WAZUH_PATH, 'var', 'multigroups', mg_name)
merged_mg_file = os.path.join(mg_folder_path, 'merged.mg')
shared_folder_path = os.path.join(WAZUH_PATH, 'etc', 'shared')
shared_file_name = 'testing_file'
shared_file_path = os.path.join(shared_folder_path, DEFAULT_TESTING_GROUP_NAME, shared_file_name)
response_data = None
elapsed_time = 2
wait_time = 1
expected_line = f"!0 {shared_file_name}"

# Configuration
local_internal_options = {'remoted.shared_reload': f"{wait_time}"}
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
test_cases_path = os.path.join(test_data_path, 'test_cases')
tcases_data = os.path.join(test_cases_path, 'case_file_actions.yaml')
configuration_parameters, configuration_metadata, test_case_ids = configuration.get_test_cases_data(tcases_data)


# Fixtures
@pytest.fixture(scope="module")
def restart_remoted():
    """Restart the wazuh-remoted daemon."""

    control_service('restart', daemon=REMOTE_DAEMON)
    check_daemon_status(target_daemon=REMOTE_DAEMON)

    yield

    control_service('stop', daemon=REMOTE_DAEMON)
    check_daemon_status(target_daemon=REMOTE_DAEMON, running_condition=False)


@pytest.fixture(scope='function')
def prepare_environment(request, register_agent):
    """Configure a custom environment for testing."""

    new_agent_group()

    agent_id = getattr(request.module, 'response_data')['id']

    sb.run([f"{tools.WAZUH_PATH}/bin/agent_groups", "-q", "-a", "-i", agent_id, "-g", 'default'])
    sb.run([f"{tools.WAZUH_PATH}/bin/agent_groups", "-q", "-a", "-i", agent_id, "-g", DEFAULT_TESTING_GROUP_NAME])

    yield

    remove_agent_group(DEFAULT_TESTING_GROUP_NAME)
    delete_file(os.path.join(groups_folder, agent_id))


@pytest.fixture(scope='function')
def register_agent(request):
    """Register an agent via API."""

    api_details = get_api_details_dict()
    data = {
        'name': agent_name,
        'ip': agent_ip
    }
    url = f"{api_details['base_url']}/agents"
    response = requests.post(url=url, headers=api_details['auth_headers'], json=data, verify=False)
    response_data = response.json()

    if response.status_code != 200:
        raise RuntimeError(f"Error registering an agent: {response_data}")

    setattr(request.module, 'response_data', response_data['data'])

    yield

    registered_agent = getattr(request.module, 'response_data')['id']
    remove_agents(agents_id=[registered_agent], remove_type='api')


def manipulate_file(action, file_path):
    if action == 'create':
        f = open(file_path, "w")
        f.close()
    else:
        delete_file(file_path)


@pytest.mark.parametrize('metadata', configuration_metadata, ids=test_case_ids)
@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
def test_merged_mg_file_content(metadata, configure_local_internal_options_module, restart_remoted,
                                prepare_environment):
    '''
    description: Check the content of the merged.mg file that wazuh-remoted compiles for multi-groups.

    wazuh_min_version: 4.2.2

    parameters:
        - metadata:
            type: dict
            brief: Metadata containing the action to execute.
        - configure_local_internal_options_module:
            type: fixture
            brief: Fixture to configure the local internal options file.
        - restart_remoted:
            type: fixture
            brief: Restart the wazuh-remoted daemon.
        - prepare_environment:
            type: fixture
            brief: Configure a custom environment for testing.

    assertions:
        - Verify that the file exists or not in the multigroups directory.
        - Verify that the file is or is not in the merged.mg file

    input_description: Different test cases defined in a YAML file.

    expected_output:
        - r'^!0 testing_file$'
    '''
    action = metadata['action']
    match_expected_line = None

    manipulate_file(action, shared_file_path)
    sleep(wait_time + elapsed_time)

    file_exists = os.path.exists(os.path.join(mg_folder_path, shared_file_name))
    if os.path.exists(merged_mg_file):
        with open(merged_mg_file, 'r') as merged_file:
            merged_file_lines = merged_file.readlines()
            match_regex = re.compile(rf".*{expected_line}.*")
            match_expected_line = list(filter(match_regex.match, merged_file_lines))
    else:
        raise FileNotFoundError(f"The file: {merged_mg_file} was not created.")

    expected_conditions = [True, [expected_line + '\n']] if action == 'create' else [False, []]
    assert file_exists == expected_conditions[0], f"The file was not {action}d in the multigroups directory.\n"
    if action == 'created':
        assert match_expected_line in expected_conditions[1], f"The file is not in {merged_mg_file}."
    else:
        match_expected_line == expected_conditions[1], f"Unexpected file found in {merged_mg_file}."
