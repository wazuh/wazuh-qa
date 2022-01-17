'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The 'wazuh-logcollector' daemon monitors configured files and commands for new log messages.
       Specifically, this test will evaluate the behaviour of wazuh when the configuration file gets
       wrong values.

tier: 0

modules:
    - logcollector

components:
    - agent
    - manager

daemons:
    - wazuh-logcollector

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
    - Windows 10
    - Windows 8
    - Windows 7
    - Windows Server 2019
    - Windows Server 2016
    - Windows Server 2012
    - Windows Server 2003
    - Windows XP

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/index.html
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html#age

tags:
    - logcollector_configuration
'''
import os
import re
import pytest
import sys
from wazuh_testing.fim import callback_configuration_error
from wazuh_testing.tools import get_service
from wazuh_testing.tools.configuration import get_wazuh_conf, write_wazuh_conf
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.services import check_daemon_status, check_if_process_is_running, control_service
from wazuh_testing.tools import WAZUH_PATH

# Variables
backup_configuration_file = get_wazuh_conf()
tested_daemon = "wazuh-logcollector"

# Marks
pytestmark = pytest.mark.tier(level=0)

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_wrong_configuration.yaml')
conf_path = os.path.join(WAZUH_PATH, 'ossec.conf') if sys.platform == 'win32' else \
    os.path.join(WAZUH_PATH, 'etc', 'ossec.conf')
agent_conf = os.path.join(WAZUH_PATH, 'shared', 'agent.conf') if sys.platform == 'win32' else \
             os.path.join(WAZUH_PATH, 'etc', 'shared', 'agent.conf')

wazuh_component = get_service()
invalid_config = {
    'option': 'log_format',
    'values': 'syslog'
}


@pytest.fixture(scope="module")
def get_configuration(request):
    """Get configurations from the module."""
    return request.param

@pytest.fixture(scope="function")
def restore_configuration_file():
    write_wazuh_conf(backup_configuration_file)
    

def add_localfile_conf(get_configuration):
    """Add agent.conf with a new configuration"""
    option, values = [get_configuration["option"], get_configuration["values"]]
    section_spaces = '  '
    option_spaces = '    '

    with open(conf_path, "r") as sources:
        lines = sources.readlines()

    with open(conf_path, 'w+') as sources:
        stop_search = False
        for line in lines:
            sources.write(line)
            if re.search(r'<\/localfile>', line) and not stop_search:
                sources.write(f'\n{section_spaces}<localfile>\n{option_spaces}<{option}>{values}</{option}>\n{section_spaces}</localfile>\n')
                stop_search = True


def edit_agent_config(get_configuration):
    """Edit agent.conf with a wrong configuration"""
    option, values = [get_configuration["option"], get_configuration["values"]]
    option_spaces = '    '


    with open(agent_conf, "r") as sources:
        lines = sources.readlines()

    with open(agent_conf, 'w+') as sources:
        stop_search = False
        for line in lines:
            sources.write(line)
            if re.search(r'<agent_config>', line) and not stop_search:
                sources.write(f'\n<localfile>\n{option_spaces}<{option}>{values}</{option}>\n</localfile>\n')
                stop_search = True


def test_invalid_configuration_logcollector(get_configuration, restart_wazuh, restore_configuration_file):
    '''
    description: -EDITAR-Check if the 'wazuh-logcollector' daemon detects invalid configurations. For this purpose, the test
                 will configure 'ossec.conf' using invalid configuration settings. Finally,
                 it will verify that error events are generated indicating the source of the errors.

    wazuh_min_version: 4.3.0

    parameters:
        - get_configuration:
            type: fixture
            brief: Get configuration from the module.
        - restart_wazuh:
            - type: fixture
            - brief: Restart the wazuh tool
        - restore_configuration_file:
            - type: fixture
            - brief: Restore the wazuh configuration file to its default value

    assertions:

    input_description: 

    expected_output:
        - 'Did not receive expected "ERROR: ...: Configuration error at event'
        - 'Did not receive expected "CRITICAL: ...: Configuration error at event'
        - 'Unexpected Daemon restarted'

    tags:
    - logcollector_configuration
    '''
    # add invalid configuration to ossec.conf
    if wazuh_component == 'wazuh-manager':
        add_localfile_conf(get_configuration)

    # add invalid configuration to agent.conf
    elif wazuh_component == 'wazuh-agent':
        edit_agent_config(get_configuration)

    # check daemons status without restart
    if wazuh_component == 'wazuh-manager':
        check_daemon_status(target_daemon='wazuh-logcollector', running_condition=True)
    elif wazuh_component == 'wazuh-agent':
        check_daemon_status(target_daemon='wazuh-agentd', running_condition=True)

    # restart daemon
    restart = True
    if wazuh_component == 'wazuh-manager':
        try:
            control_service('restart', 'wazuh-logcollector')

        except:
            restart = False
            check_daemon_status(target_daemon='wazuh-logcollector', running_condition=False)
            # check logs
            wazuh_log_monitor.start(timeout=3, callback=callback_configuration_error,
                                    error_message='Did not receive expected '
                                                  '"CRITICAL: ...: Configuration error at" event')
            restore_configuration_file
            control_service('restart', 'wazuh-logcollector')
        if restart == True:
            restore_configuration_file
            raise ValueError('Unexpected Daemon restarted')

    elif wazuh_component == 'wazuh-agent':
        restart_wazuh
        check_daemon_status(target_daemon='wazuh-agentd', running_condition=True)
        # check logs
        wazuh_log_monitor.start(timeout=3, callback=callback_configuration_error,
                                error_message='Did not receive expected '
                                              '"ERROR: ...: Configuration error at" event')
