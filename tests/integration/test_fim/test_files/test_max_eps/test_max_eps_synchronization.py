'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts
       when these files are modified. Specifically, these tests will verify that FIM limits
       the maximum synchronization message throughput, set in the 'max_eps' tag.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured
       files for changes to the checksums, permissions, and ownership.

tier: 1

modules:
    - fim

components:
    - agent

daemons:
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
    - Windows 10
    - Windows 8
    - Windows 7
    - Windows Server 2019
    - Windows Server 2016
    - Windows Server 2012
    - Windows Server 2003
    - Windows XP

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html#synchronization

pytest_args:
    - fim_mode:
        realtime: Enable real-time monitoring on Linux (using the 'inotify' system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the 'who-data' information.
        scheduled: Implies scheduled scan

    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - fim_max_eps
    - fim_max_eps_sync
'''
import os
import shutil
import sys
import pytest

from collections import Counter
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.fim import LOG_FILE_PATH, REGULAR, create_file, generate_params 

from wazuh_testing.modules import (DATA, TIER1, AGENT, WINDOWS, LINUX)
from wazuh_testing.modules.fim import (TEST_DIR_1, TEST_DIRECTORIES, YAML_CONF_MAX_EPS_SYNC, ERR_MSG_WRONG_VALUE_MAXIMUM_FILE_SIZE, ERR_MSG_INTEGRITY_CONTROL_MSG)
from wazuh_testing.modules.fim.event_monitor import callback_integrity_message, callback_connection_message


# Marks
pytestmark = [TIER1, AGENT, WINDOWS, LINUX]

# Variables
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), DATA)
configurations_path = os.path.join(test_data_path, YAML_CONF_MAX_EPS_SYNC)

test_directories = [os.path.join(PREFIX, TEST_DIR_1)]
conf_params = {TEST_DIRECTORIES: test_directories[0]}

# Configurations
eps_values = ['50', '10']
#eps_values = ['0', '1', '50', '499','1000', '2000']
parameters, metadata = generate_params(extra_params=conf_params, apply_to_all=({'MAX_EPS': eps_value} for eps_value in eps_values))
configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)


# Fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.fixture(scope='module')
def create_files(get_configuration):
    max_eps = get_configuration['metadata']['max_eps']
    for i in range(int(max_eps) * 5):
        create_file(REGULAR, test_directories[0], f'test{i}_{max_eps}', content='')


@pytest.fixture(scope='function')
def delete_files():
    yield
    for test_dir in test_directories:
        shutil.rmtree(test_dir, ignore_errors=True)

# Tests

def test_max_eps_on_start(get_configuration, create_files, configure_environment, restart_wazuh, delete_files):
    '''
    description: Check if the 'wazuh-syscheckd' daemon applies the limit set in the 'max_eps' tag when
                 a lot of synchronization events are generated. For this purpose, the test will monitor
                 a folder and create multiple testing files in it. Once FIM is started, it will wait for
                 the agent to connect to the manager and generate an integrity message. Then, the test
                 will collect FIM 'integrity' events generated and check if the number of events matches
                 the testing files created. Finally, it will verify the limit of events per second (eps)
                 is not exceeded by checking the creation time of the testing files.

    wazuh_min_version: 4.2.0

    parameters:
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - create_files:
            type: fixture
            brief: Create the testing files to be monitored.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - restart_wazuh:
            type: fixture
            brief: Clear the 'ossec.log' file and start a new monitor.
        - delete_files:
            type: fixture
            brief: Delete the testing files when the test ends.

    assertions:
        - Verify that FIM 'integrity' events are generated for each testing file created.
        - Verify that the eps limit set in the 'max_eps' tag has not been exceeded at generating FIM events.

    input_description: A test case (max_eps_synchronization) is contained in external YAML file
                       (wazuh_conf_synchro.yaml) which includes configuration settings for
                       the 'wazuh-syscheckd' daemon and, these are combined with the
                       testing directories to be monitored defined in the module.

    expected_output:
        - r'.* Connected to the server .*'
        - r'.*Sending integrity control message'

    tags:
        - realtime
        - scheduled

    '''
    max_eps = int(get_configuration['metadata']['max_eps'])

    # Wait until the agent connects to the manager.
    wazuh_log_monitor.start(timeout=90,
                            callback=callback_connection_message,
                            error_message=ERR_MSG_WRONG_VALUE_MAXIMUM_FILE_SIZE).result()

    #  Find integrity start before attempting to read max_eps
    wazuh_log_monitor.start(timeout=30,
                            callback=callback_integrity_message,
                            error_message=ERR_MSG_INTEGRITY_CONTROL_MSG).result()

    n_results = max_eps * 5
    result = wazuh_log_monitor.start(timeout=120,
                                     accum_results=n_results,
                                     callback=callback_integrity_message,
                                     error_message=f'Received less results than expected ({n_results})').result()

    counter = Counter([date_time for date_time, _ in result])
    error_margin = (max_eps * 0.1)

    for _, n_occurrences in counter.items():
        assert n_occurrences <= round(
            max_eps + error_margin), f'Sent {n_occurrences} but a maximum of {max_eps} was set'
