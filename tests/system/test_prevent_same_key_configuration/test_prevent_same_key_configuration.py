'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: system

brief: When the manager receives the same key configuration from a new agent (with a different socket number) the new
       connection must be rejected by the manager if the auto-enrollment option is disabled (until the first agent
       gets disconnected). When the auto-enrollment option is enabled, the manager must assign a new key
       configuration to the new agent.

tier: 0

modules:
    - remoted

components:
    - manager
    - agent

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
    - CentOS 6
    - Ubuntu Focal
    - Ubuntu Bionic
    - Ubuntu Xenial
    - Ubuntu Trusty
    - Debian Buster
    - Debian Stretch
    - Debian Jessie
    - Debian Wheezy
    - Red Hat 8
    - Red Hat 7
    - Red Hat 6

references:
    - https://documentation.wazuh.com/current/user-manual/registering/index.html
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/client.html#enrollment
    - https://documentation.wazuh.com/current/user-manual/agents/agent-life-cycle.html

tags:
    - remoted
'''

import re
import pytest
import os

from wazuh_testing.tools.file import read_json_file

expected_message_regex = r"(\d+\/)+\d+ (\d+:)+\d+ wazuh-remoted: WARNING.*\'001\'"
no_enrollment_expected_status = ['Active', 'Disconnected', 'Active']
enrollment_expected_status = ['Active', 'Active']


@pytest.fixture
def get_log_output(request):
    """Allow getting the last lines of the ossec.log file.

    Args:
        request (fixture): Provide information on the executing test function.
    """
    return request.config.getoption('--log-output')


@pytest.fixture
def get_control_output(request):
    """Allow getting the agent_control output file.

    Args:
        request (fixture): Provide information on the executing test function.
    """
    return request.config.getoption('--control-output')


def get_only_agents_info(file_path):
    control_output = read_json_file(file_path)
    agents_info = []
    for _, output in enumerate(control_output):
        output['data'].pop(0)
        control_output[_] = output['data']
        agents_info.extend([agent_info for agent_info in control_output[_]])
    return agents_info


def test_prevent_same_key_config(get_log_output, get_control_output):
    '''
    description: When the manager receives the same key configuration from a new agent (with a different socket number)
                 the new connection must be rejected by the manager if the auto-enrollment option is disabled (until
                 the first agent gets disconnected). When the auto-enrollment option is enabled, the manager must
                 assign a new key configuration to the new agent. This test aims to check those behaviors.

    wazuh_min_version: 4.3.0

    parameters:
        - get_log_output:
            type: fixture
            brief: Allow getting the last lines of the ossec.log file.
        - get_control_output:
            type: fixture
            brief: Allow getting the agent_control output file.

    assertions:
        - Check that the rejected message is present in the log file
        - Check that the status of the agents are the expected.
        - Check that the id of the agents are the expected.

    input_description: The last lines of the ossec.log file and the agent_control output in JSON format.

    expected_output:
        - The actual behavior was not the expected.
        - Both agents must be active.
        - Agents ID`s must be different.

    tags:
        - remoted
    '''

    agents_info = get_only_agents_info(get_control_output)
    agents_status = []
    agents_ids = []
    for agent in agents_info:
        agents_status.append(agent['status'])
        agents_ids.append(agent['id'])

    if os.path.isfile(get_log_output):
        pattern = re.compile(expected_message_regex)
        line_found = False
        for line in open(get_log_output):
            for _ in re.finditer(pattern, line):
                line_found = True
                break
        assert line_found, 'The expected message was not present in the ossec.log file.\n'

        assert no_enrollment_expected_status == agents_status, 'The actual behavior was not the expected.\n' \
                                                               f'Actual result: {agents_status}' \
                                                               'Expected result: When enrollment is disabled,' \
                                                               ' the second agent will only connect to the ' \
                                                               'manager when the first agent disconnects.\n'

        assert agents_ids[0] == agents_ids[1] and agents_ids[0] == agents_ids[2], 'The actual behavior was not the ' \
                                                                                  'expected.\n' \
                                                                                  'Actual result: The agents IDs are' \
                                                                                  f' {agents_ids}\n' \
                                                                                  f'Expected result: Connections' \
                                                                                  f' must have the same agent ID.\n'
    else:
        assert enrollment_expected_status == agents_status, 'Both agents must be active.\n' \
                                                            f'Actual result: {agents_status}\n'
        assert agents_ids[0] != agents_ids[1], 'Agents ID`s must be different.\n' \
                                               f'Actual result: {agents_ids}\n'
