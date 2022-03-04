'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts
       when these files are modified. Specifically, these tests will verify that FIM limits
       the maximum events per second that it generates, set in the 'max_eps' tag.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured
       files for changes to the checksums, permissions, and ownership.

components:
    - fim

suite: files_max_eps

targets:
    - agent
    - manager

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
    - Debian Buster
    - Red Hat 8
    - Ubuntu Focal
    - Ubuntu Bionic
    - Windows 10
    - Windows Server 2019
    - Windows Server 2016

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html#synchronization

pytest_args:
    - fim_mode:
        realtime: Enable real-time monitoring on Linux (using the 'inotify' system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the 'who-data' information.
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - fim_max_eps
'''
import os
from collections import Counter

import pytest
from wazuh_testing.fim import LOG_FILE_PATH, REGULAR, create_file, generate_params, callback_event_message, \
    check_time_travel
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = pytest.mark.tier(level=1)

# Variables
test_directories = [os.path.join(PREFIX, 'testdir1')]

directory_str = ','.join(test_directories)

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
testdir1 = os.path.join(PREFIX, 'testdir1')

# Configurations
conf_params = {'TEST_DIRECTORIES': directory_str,
               'MODULE_NAME': __name__}

eps_values = ['50', '10']

p, m = generate_params(extra_params=conf_params, apply_to_all=({'MAX_EPS': eps_value} for eps_value in eps_values),
                       modes=['scheduled'])
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# Fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_max_eps(get_configuration, configure_environment, restart_syscheckd, wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon applies the limit set in the 'max_eps' tag when
                 a lot of 'syscheck' events are generated. For this purpose, the test will monitor a folder,
                 and once FIM is started, it will create multiple testing files in it. Then, the test
                 will collect FIM 'added' events generated and check if the number of events matches
                 the testing files created. Finally, it will verify the limit of events per second (eps)
                 is not exceeded by checking the creation time of the testing files.

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
        - Verify that FIM events are generated for each testing file created.
        - Verify that the eps limit set in the 'max_eps' tag has not been exceeded at generating FIM events.

    input_description: A test case (max_eps) is contained in external YAML file (wazuh_conf.yaml) which
                       includes configuration settings for the 'wazuh-syscheckd' daemon and, these are
                       combined with the testing directory to be monitored defined in the module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added' events)

    tags:
        - realtime
        - scheduled
    '''
    check_apply_test({'max_eps'}, get_configuration['tags'])

    max_eps = int(get_configuration['metadata']['max_eps'])
    mode = get_configuration['metadata']['fim_mode']

    # Create files to read max_eps files with added events
    for i in range(int(max_eps) * 5):
        create_file(REGULAR, testdir1, f'test{i}_{mode}_{max_eps}', content='')

    check_time_travel(mode == "scheduled")
    n_results = max_eps * 5

    result = wazuh_log_monitor.start(timeout=(n_results / max_eps) * 6,
                                     accum_results=n_results,
                                     callback=callback_event_message,
                                     error_message=f'Received less results than expected ({n_results})').result()

    counter = Counter([date_time for date_time, _ in result])
    error_margin = (max_eps * 0.1)

    for _, n_occurrences in counter.items():
        assert n_occurrences <= round(
            max_eps + error_margin), f'Sent {n_occurrences} but a maximum of {max_eps} was set'
