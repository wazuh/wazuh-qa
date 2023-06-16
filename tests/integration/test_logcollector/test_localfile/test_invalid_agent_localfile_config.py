'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The 'wazuh-logcollector' daemon monitors configured files and commands for new log messages. When Wazuh is
       configured incorrectly then a configuration error is displayed in the Wazuh's log, and Wazuh does not start (if
       it has been restarted previously).

tier: 0

modules:
    - logcollector

components:
    - agent

daemons:
    - wazuh-logcollector

os_platform:
    - linux
    - windows

os_version:
    - Amazon Linux 1
    - Amazon Linux 2
    - Arch Linux
    - Debian Buster
    - Debian Stretch
    - Debian Jessie
    - Debian Wheezy
    - CentOS 6
    - CentOS 7
    - CentOS 8
    - Fedora 31
    - Fedora 32
    - Fedora 33
    - Fedora 34
    - openSUSE 42
    - Oracle 6
    - Oracle 7
    - Oracle 8
    - Red Hat 6
    - Red Hat 7
    - Red Hat 8
    - Solaris 10
    - Solaris 11
    - SUSE 12
    - SUSE 13
    - SUSE 14
    - SUSE 15
    - Ubuntu Bionic
    - Ubuntu Trusty
    - Ubuntu Xenial
    - Ubuntu Focal
    - macOS Server
    - macOS Catalina
    - Windows XP
    - Windows 7
    - Windows 8
    - Windows 10
    - Windows Server 2003
    - Windows Server 2012
    - Windows Server 2016
    - Windows Server 2019

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/index.html
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html#location
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html#log-format

tags:
    - logcollector
'''
import os
import tempfile

import pytest

from wazuh_testing.tools import LOGCOLLECTOR_DAEMON, LOG_FILE_PATH
from wazuh_testing.tools.services import check_daemon_status
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.utils import lower_case_key_dictionary_array
from wazuh_testing.fim import callback_configuration_error
from wazuh_testing.logcollector import LOG_COLLECTOR_GLOBAL_TIMEOUT, callback_missing_element_error


# Marks
pytestmark = [pytest.mark.tier(level=0), pytest.mark.agent]

# Variables
files = ['test.txt']

# Configuration
daemons_handler_configuration = {
    'daemons': [LOGCOLLECTOR_DAEMON]
}

temp_dir = tempfile.gettempdir()
file_structure = [
    {
        'folder_path': os.path.join(temp_dir, 'wazuh-testing'),
        'filename': files
    }
]

parameters = [
    {'LOCATION': os.path.join(temp_dir, 'wazuh-testing', files[0]), 'LOG_FORMAT': None},
    {'LOCATION': None, 'LOG_FORMAT': 'syslog'},
]
metadata = lower_case_key_dictionary_array(parameters)

tcase_ids = [f"location_{'None' if param['LOCATION'] is None else files[0]}_"
             f"logformat_{'None' if param['LOG_FORMAT'] is None else param['LOG_FORMAT']}" for param in parameters]
configurations_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data', 'invalid_agent_conf.yaml')
configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)


@pytest.fixture(scope="module")
def get_files_list():
    """Get file list to create from the module."""
    return file_structure


@pytest.fixture(scope="module", params=configurations, ids=tcase_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Tests

def test_invalid_agent_localfile_config(get_files_list, create_file_structure_module, get_configuration, set_agent_conf,
                                        daemons_handler_module):
    '''
    description: Check if the expected message is present in the ossec.log when an invalid <localfile> configuration is
                 set and if the Wazuh continues running.

    wazuh_min_version: 4.3.0

    parameters:
        - get_files_list:
            type: fixture
            brief: Get file list to create from the module.
        - create_file_structure_module:
            type: fixture
            brief: Module scope version of create_file_structure.
        - get_configuration:
            type: fixture
            brief: Get configuration from the module.
        - set_agent_conf:
            type: fixture
            brief: Set a new configuration in 'agent.conf' file.
        - daemons_handler_module:
            type: fixture
            brief: Handler of Wazuh daemons.

    assertions:
        - Verify that the expected error message is in the log

    input_description: A YAML file with the invalid configurations.

    expected_output:
        - Did not receive expected "ERROR: Configuration error at" event
        - Did not receive the expected "ERROR: Missing ... element." event.

    tags:
        - logcollector
    '''
    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

    check_daemon_status(target_daemon=LOGCOLLECTOR_DAEMON, running_condition=True)

    wazuh_log_monitor.start(timeout=LOG_COLLECTOR_GLOBAL_TIMEOUT, callback=callback_missing_element_error,
                            error_message='Did not receive the expected "ERROR: ...: Missing ... element.')

    wazuh_log_monitor.start(timeout=LOG_COLLECTOR_GLOBAL_TIMEOUT, callback=callback_configuration_error,
                            error_message='Did not receive the expected "ERROR: ...: Configuration error at" event')
