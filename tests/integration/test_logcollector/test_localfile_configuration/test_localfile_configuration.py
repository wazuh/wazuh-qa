# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import re
import pytest
import sys
from wazuh_testing.fim import callback_configuration_error
from wazuh_testing.tools import get_service
from wazuh_testing.tools.configuration import get_wazuh_conf, write_wazuh_conf
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.services import check_daemon_status, check_if_process_is_running, control_service
from wazuh_testing.tools import WAZUH_PATH

tested_daemon = "wazuh-logcollector"

# Marks
pytestmark = pytest.mark.tier(level=0)

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

# Configuration
conf_path = os.path.join(WAZUH_PATH, 'ossec.conf') if sys.platform == 'win32' else \
    os.path.join(WAZUH_PATH, 'etc', 'ossec.conf')
agent_conf = os.path.join(WAZUH_PATH, 'etc', 'shared', 'agent.conf')

wazuh_component = get_service()
invalid_config = {
    'option': 'log_format',
    'values': 'syslog'
}


@pytest.fixture(scope="module", params=[invalid_config])
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def add_localfile_conf(get_configuration):
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


def test_invalid_configuration_logcollector(get_configuration):
    '''
    description: -EDITAR-Check if the 'wazuh-logcollector' daemon detects invalid configurations. For this purpose, the test
                 will configure 'ossec.conf' using invalid configuration settings. Finally,
                 it will verify that error events are generated indicating the source of the errors.

    wazuh_min_version: 4.3.0

    parameters:

    assertions:

    input_description: 

    expected_output:
        -

    '''
    # Save current configuration
    backup_config = get_wazuh_conf()

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
            write_wazuh_conf(backup_config)
            control_service('restart', 'wazuh-logcollector')
        if restart == True:
            write_wazuh_conf(backup_config)
            raise ValueError('Unexpected Daemon restarted')

    elif wazuh_component == 'wazuh-agent':
        control_service('restart', 'wazuh-agentd')
        check_daemon_status(target_daemon='wazuh-agentd', running_condition=True)
        # check logs
        wazuh_log_monitor.start(timeout=3, callback=callback_configuration_error,
                                error_message='Did not receive expected '
                                              '"ERROR: ...: Configuration error at" event')
