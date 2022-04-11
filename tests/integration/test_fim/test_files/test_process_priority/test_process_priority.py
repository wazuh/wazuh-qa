'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when
       these files are modified. Specifically, these tests will check if the process priority of
       the 'wazuh-syscheckd' daemon set in the 'process_priority' tag is applied successfully.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks
       configured files for changes to the checksums, permissions, and ownership.

components:
    - fim

suite: files_process_priority

targets:
    - agent
    - manager

daemons:
    - wazuh-syscheckd

os_platform:
    - linux
    - windows
    - macos
    - solaris

os_version:
    - Arch Linux
    - Amazon Linux 2
    - Amazon Linux 1
    - CentOS 8
    - CentOS 7
    - Debian Buster
    - Red Hat 8
    - Solaris 10
    - Solaris 11
    - macOS Catalina
    - macOS Server
    - Ubuntu Focal
    - Ubuntu Bionic
    - Windows 10
    - Windows Server 2019
    - Windows Server 2016

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html#process-priority

pytest_args:
    - fim_mode:
        realtime: Enable real-time monitoring on Linux (using the 'inotify' system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the 'who-data' information.
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - fim_process_priority
'''
import os
import sys

import pytest
from wazuh_testing.fim import generate_params
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.services import get_process

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.darwin, pytest.mark.sunos5, pytest.mark.tier(level=1)]

# variables

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
force_restart_after_restoring = True
test_directories = [os.path.join(PREFIX, 'testdir1')]

# configurations

priority_list = ['0', '4', '-5']
test_modes = ['realtime'] if sys.platform == 'linux' else ['scheduled']
conf_params = {'TEST_DIRECTORIES': test_directories[0], 'MODULE_NAME': __name__}

p, m = generate_params(apply_to_all=({'PROCESS_PRIORITY': priority_value} for priority_value in priority_list),
                       extra_params=conf_params, modes=test_modes)

configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# fixtures
@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests

def test_process_priority(get_configuration, configure_environment, restart_syscheckd, wait_for_fim_start):
    '''
    description: Check if the process priority of the 'wazuh-syscheckd' daemon set in the 'process_priority' tag
                 is updated correctly. For this purpose, the test will monitor a testing folder and, once FIM starts,
                 it will get the priority value from the 'process_priority' tag and the system information of
                 the 'wazuh-syscheckd' process. Finally, the test will compare the current process priority
                 with the target priority to verify that they match.

    wazuh_min_version: 4.2.0

    tier: 1

    parameters:
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - restart_syscheckd:
            type: fixture
            brief: Clear the 'ossec.log' file and start a new monitor.
        - wait_for_fim_start:
            type: fixture
            brief: Wait for realtime start, whodata start, or end of initial FIM scan.

    assertions:
        - Verify that the 'wazuh-syscheckd' daemon is running.
        - Verify that the process priority of the 'wazuh-syscheckd' daemon matches the 'process_priority' tag.

    input_description: A test case (ossec_conf) is contained in external YAML file (wazuh_conf.yaml)
                       which includes configuration settings for the 'wazuh-syscheckd' daemon and,
                       these are combined with the testing directory to be monitored defined in the module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added' events)
        - r'.*Ignoring .* due to'

    tags:
        - realtime
        - scheduled
    '''
    check_apply_test({'ossec_conf'}, get_configuration['tags'])

    priority = int(get_configuration['metadata']['process_priority'])
    process_name = 'wazuh-syscheckd'
    syscheckd_process = get_process(process_name)

    assert syscheckd_process is not None, f'Process {process_name} not found'
    assert (os.getpriority(os.PRIO_PROCESS, syscheckd_process.pid)) == priority, \
        f'Process {process_name} has not updated its priority.'
