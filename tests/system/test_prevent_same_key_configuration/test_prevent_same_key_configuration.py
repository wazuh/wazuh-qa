'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: system

brief:

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
    -

tags:
    - remoted
'''

import re
import pytest
import os

from wazuh_testing.tools.file import read_json_file

expected_message_regex = r"(\d+\/)+\d+ (\d+:)+\d+ wazuh-remoted: WARNING.*\'001\'"


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


def test_prevent_same_key_config(get_log_output, get_control_output):
    '''
    description: This test aims to compare the average of dropped events before and after
                 the upgrade of the manager, and checks if the ingestion rate does
                 not decrease.

    wazuh_min_version: 4.2.0

    parameters:
        - get_first_result:
            type: fixture
            brief: Get the file path of the results before upgrading Wazuh.
        - get_second_result:
            type: fixture
            brief: Get the file path of the results after upgrading Wazuh.

    assertions:
        - Verify that the ingestion rate does not decreased after upgrading
          Wazuh.

    input_description: The results of stress analysisd, before and after
                       upgrading Wazuh, are stored in 2 files. They contain
                       the necessary data for the test to compare them.

    expected_output:
        - A JSON with the result of the test.
        - The ingestion rate decreased after the upgrade,
          check the results within /path/to/result/file

    tags:
        - analysisd
    '''

    control_output = read_json_file(get_control_output)['data']
    control_output.pop(0)
    agents_status = []
    agents_ids = []
    for agent in control_output:
        agents_status.append(agent['status'])
        agents_ids.append(agent['id'])

    if os.path.isfile(get_log_output):
        pattern = re.compile(expected_message_regex)
        line_found = False
        for line in open(get_log_output):
            for _ in re.finditer(pattern, line):
                line_found = True
                break
        assert line_found, 'The message was not present in the ossec.log file.'

        assert ['Disconnected', 'Active'] == agents_status, 'The actual behaviour was not the expected.\n' \
                                                            f'Actual result: 1st agent status was {agents_status[0]}' \
                                                            f' and 2nd agent status was {agents_status[1]}.\n' \
                                                            'Expected result: When enrollment is disabled, the second' \
                                                            ' agent will only connect to the manager when the' \
                                                            ' first agent disconnects.\n'

        assert ['001', '001'] == agents_ids, 'The actual behaviour was not the expected.\n' \
                                             f'Actual result: The agents IDs are {agents_ids}\n' \
                                             f'Expected result: Both connections must have the same agent ID.\n'
    else:
        assert ['001', '002'] in agents_ids, 'MAL, tienen que ser difrentes IDs compaaa.\n' \
                                             'esperado: 001 y 002.\n' \
                                             f'obtenido: {agents_ids}\n'
