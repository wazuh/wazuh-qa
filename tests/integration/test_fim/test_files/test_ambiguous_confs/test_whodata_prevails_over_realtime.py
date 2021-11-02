'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check if the 'who-data' feature of the File Integrity Monitoring (FIM) system
       works properly. 'who-data' information contains the user who made the changes on the monitored
       files and also the program name or process used to carry them out. In particular, it will be
       verified that the value of the 'whodata' attribute prevails over the 'realtime' one.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured files
       for changes to the checksums, permissions, and ownership.

tier: 2

modules:
    - fim

components:
    - manager

daemons:
    - wazuh-syscheckd

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
    - https://documentation.wazuh.com/current/user-manual/capabilities/auditing-whodata/who-linux.html
    - https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html

pytest_args:
    - fim_mode:
        realtime: Enable real-time monitoring on Linux (using the 'inotify' system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the 'who-data' information.
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - fim_ambiguous_confs
'''
import os

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import (LOG_FILE_PATH, generate_params, callback_detect_event,
                               REGULAR, create_file, delete_file)
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor

# Marks
pytestmark = pytest.mark.tier(level=2)

# Variables and configuration
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

test_directories = [os.path.join(PREFIX, 'testdir1'),
                    os.path.join(PREFIX, 'testdir2')
                    ]
dir1, dir2 = test_directories

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf_whodata_prevails_over_realtime.yaml')

conf_params = {'TEST_DIR1': dir1, 'TEST_DIR2': dir2, 'MODULE_NAME': __name__}
p, m = generate_params(extra_params=conf_params, modes=['whodata'])

configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# Fixture
@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Test
@pytest.mark.parametrize('directory', [
    dir1,
    dir2,
])
def test_whodata_prevails_over_realtime(directory, get_configuration, put_env_variables, configure_environment,
                                        restart_syscheckd, wait_for_fim_start):
    '''
    description: Check if when using the options who-data and real-time at the same time
                 the value of 'whodata' is the one used. For example, when using 'whodata=yes'
                 and 'realtime=no' on the same directory, real-time file monitoring
                 will be enabled, as who-data requires it.
                 For this purpose, the configuration is applied and it is verified that when
                 'who-data' is set to 'yes', the 'realtime' value is not taken into account,
                 enabling in this case the real-time file monitoring.

    wazuh_min_version: 4.2.0

    parameters:
        - directory:
            type: str
            brief: Testing directory.
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - put_env_variables:
            type: fixture
            brief: Create environment variables.
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
        - Verify that real-time file monitoring is active.

    input_description: A test case is contained in external YAML file
                       (wazuh_conf_whodata_prevails_over_realtime.yaml)
                       which includes configuration settings for the 'wazuh-syscheckd' daemon
                       and testing directories to monitor.

    expected_output:
        - r'.*Sending FIM event: (.+)$'

    tags:
        - realtime
        - who-data
    '''
    filename = "testfile"

    create_file(REGULAR, directory, filename, content="")
    event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                    callback=callback_detect_event).result()

    if (event['data']['mode'] != 'whodata' and event['data']['type'] != 'added' and
            os.path.join(directory, filename) in event['data']['path']):
        raise AssertionError('Event not found')

    delete_file(directory, filename)
    event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                    callback=callback_detect_event).result()

    if (event['data']['mode'] != 'whodata' and event['data']['type'] != 'deleted' and
            os.path.join(directory, filename) in event['data']['path']):
        raise AssertionError('Event not found')
