'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The 'wazuh-logcollector' daemon monitors configured files and commands for new log messages. When Wazuh is
       configured incorrectly then a configuration error is displayed in the Wazuh's log, and Wazuh does not start
       (if it is restarted).

tier: 0

modules:
    - logcollector

components:
    - agent
    - manager

daemons:
    - wazuh-logcollector
    - wazuh-agentd

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
    - logcollector
'''
import os
import sys
import tempfile

import pytest

from wazuh_testing.tools import get_service, LOGCOLLECTOR_DAEMON, AGENT_DAEMON
from wazuh_testing.tools import WAZUH_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.fim import callback_configuration_error


# Marks
pytestmark = pytest.mark.tier(level=0)

# Variables
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
wazuh_component = get_service()
temp_dir = tempfile.gettempdir()

# Configuration
daemons_handler_configuration = {
    'daemons': [LOGCOLLECTOR_DAEMON if 'manager' in wazuh_component else AGENT_DAEMON],
    'ignore_errors': True
}
cases = [
    # Case 1: <location> not present
    {
        'params': {
            'LOG_FORMAT': 'syslog'
        },
        'metadata': {
            'regex': callback_configuration_error
        }
    }
]
params = [case['params'] for case in cases]
metadata = [case['metadata'] for case in cases]
tcase_ids = [f"location_None_logformat_{param['LOG_FORMAT']}" for param in params]
configurations_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data', 'location_config.yaml')
configurations = load_wazuh_configurations(configurations_path, __name__, params=params, metadata=metadata)
agent_conf = os.path.join(WAZUH_PATH, 'shared', 'agent.conf') if sys.platform == 'win32' else \
             os.path.join(WAZUH_PATH, 'etc', 'shared', 'agent.conf')


@pytest.fixture(scope="module", params=configurations, ids=tcase_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_invalid_configuration_logcollector(get_configuration, configure_environment, daemons_handler):
    '''
    description: 

    wazuh_min_version: 4.3.0

    parameters:
        - get_configuration:
            type: fixture
            brief: Get configuration from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing. Restart Wazuh is needed for applying the configuration.
        - daemons_handler:
            type: fixture
            brief: Handler of Wazuh daemons.

    assertions:

    input_description: The 'invalid_configuration' includes the wrong configuration for the ossec.conf.

    expected_output:
        - 'Did not receive expected "CRITICAL: ...: Configuration error at event'

    tags:
        - logcollector
    '''
    metadata = get_configuration.get('metadata')
    wazuh_log_monitor.start(timeout=5, callback=metadata['regex'],
                            error_message='Did not receive the expected "CRITICAL: ...: Configuration error at" event')
