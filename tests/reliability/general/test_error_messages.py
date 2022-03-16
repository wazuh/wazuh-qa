'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: reliability

brief: All Wazuh components generate log messages. These can be DEBUG, WARNING, ERROR, CRITICAL. 
       Unexpected errors/warnings/critical should not be generated.

tier: 0

modules:
    - active_response
    - agentd
    - analysisd
    - api
    - authd
    - cluster
    - fim
    - gcloud
    - github
    - logcollector
    - logtest
    - office365
    - remoted
    - rids
    - rootcheck
    - vulnerability_detector
    - wazuh_db
    - wpk

components:
    - agent
    - manager

daemons:
    - wazuh-agentd
    - wazuh-agentlessd
    - wazuh-analysisd
    - wazuh-authd
    - wazuh-csyslogd
    - wazuh-apid
    - wazuh-clusterd
    - wazuh-db
    - wazuh-dbd
    - wazuh-execd
    - wazuh-integratord
    - wazuh-logcollector
    - wazuh-maild
    - wazuh-monitord
    - wazuh-modulesd
    - wazuh-remoted
    - wazuh-reportd
    - wazuh-syscheckd

os_platform:
    - linux
    - windows

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
    - macOS Server
    - macOS Catalina
    - macOS Sierra
    - Windows XP
    - Windows 7
    - Windows 8
    - Windows 10
    - Windows Server 2003
    - Windows Server 2012
    - Windows Server 2016
    - Windows Server 2019
'''
import json
import os
import re

import pytest

from wazuh_testing import global_parameters

error_codes = ['warning', 'error', 'critical']
known_messages_filename = 'know_messages.json'
known_messages_path = os.path.join(os.path.dirname(__file__), known_messages_filename)


target = ['agents', 'managers'] if not global_parameters.target_hosts else global_parameters.target_hosts


def get_log_daemon(log_line):
    pattern = re.compile(".*\d+\/\d+\/\d+ \d+:\d+:\d+ (.*?):")
    if pattern.match(log_line):
        return pattern.match(log_line).group(1)
    else:
        return None


@pytest.mark.parametrize('code', error_codes)
@pytest.mark.parametrize('target', target)
def test_error_messages(get_report, code, target):
    '''
    description: Check if unexpected error, warning or critical occurs in the environment

    wazuh_min_version: 4.4.0

    parameters:
        - get_report:
            type: fixture
            brief: Get the JSON environment report.

    assertions:
        - Verify that no unexpected warning, error or critical appears in any of the hosts.

    input_description: JSON environment reports

    expected_output:
        - None
    '''
    unexpected_errors = []
    with open(known_messages_path) as f:
        expected_error_messages = json.loads(f.read())

    for target_messages in get_report[target][code]:
        for error_messages in target_messages.values():
            for error_message in error_messages:
                target_message = True
                if global_parameters.target_daemons:
                    target_message = False
                    for daemon in global_parameters.target_daemons:
                        if get_log_daemon(error_message) == daemon:
                            target_message = True
                            break            
                if target_message:
                    known_error = False
                    if expected_error_messages[code]:
                        combined_known_regex = '(' + ')|('.join(expected_error_messages[code]) + ')'
                        known_error = re.match(combined_known_regex, error_message)

                    if not known_error:
                        unexpected_errors += [error_message]

    assert not unexpected_errors, f"Unexpected error message detected {unexpected_errors}"
