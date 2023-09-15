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
import sys
import pytest
import time

from collections import Counter
from wazuh_testing import logger, LOG_FILE_PATH
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor, generate_monitoring_callback
from wazuh_testing.tools.file import write_file
from wazuh_testing.modules.fim import TEST_DIR_1, REALTIME_MODE, WHODATA_MODE
from wazuh_testing.modules.fim import FIM_DEFAULT_LOCAL_INTERNAL_OPTIONS as local_internal_options
from wazuh_testing.modules.fim.event_monitor import (ERR_MSG_MULTIPLE_FILES_CREATION, callback_integrity_message,
                                                     CB_PATH_MONITORED_REALTIME, ERR_MSG_MONITORING_PATH,
                                                     CB_PATH_MONITORED_WHODATA, CB_PATH_MONITORED_WHODATA_WINDOWS)
from wazuh_testing.modules.fim.utils import generate_params


# Marks
pytestmark = pytest.mark.tier(level=1)

# Variables
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
test_directories = [os.path.join(PREFIX, TEST_DIR_1)]
TIMEOUT = 180

# Configurations
conf_params = {'TEST_DIRECTORIES': test_directories[0]}

eps_values = ['50', '10']

p, m = generate_params(extra_params=conf_params, apply_to_all=({'MAX_EPS': eps_value} for eps_value in eps_values),
                       modes=[REALTIME_MODE, WHODATA_MODE])
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# Fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def create_multiple_files(get_configuration):
    """Create multiple files of a specific type."""
    max_eps = get_configuration['metadata']['max_eps']
    mode = get_configuration['metadata']['fim_mode']
    try:
        for i in range(int(max_eps) * 4):
            file_name = f'file{i}_to_max_eps_{max_eps}_{mode}_mode{time.time()}'
            path = os.path.join(test_directories[0], file_name)
            write_file(path)
    except OSError:
        logger.info(ERR_MSG_MULTIPLE_FILES_CREATION)


@pytest.mark.skip("This test is affected by Issue #15844, when it is fixed it should be enabled again.")
def test_max_eps(configure_local_internal_options_module, get_configuration, configure_environment, restart_wazuh):
    '''
    description: Check if the 'wazuh-syscheckd' daemon applies the limit set in the 'max_eps' tag when
                 a lot of 'syscheck' events are generated. For this purpose, the test will monitor a folder,
                 and once FIM is started, it will create multiple testing files in it. Then, the test
                 will collect FIM 'added' events generated and check if the number of events matches
                 the testing files created. Finally, it will verify the limit of events per second (eps)
                 is not exceeded by checking the creation time of the testing files.

    wazuh_min_version: 4.6.0

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
        - scheduled
    '''
    max_eps = int(get_configuration['metadata']['max_eps'])
    mode = get_configuration['metadata']['fim_mode']
    if sys.platform == 'win32':
        monitoring_regex = CB_PATH_MONITORED_REALTIME if mode == 'realtime' else CB_PATH_MONITORED_WHODATA_WINDOWS
    else:
        monitoring_regex = CB_PATH_MONITORED_REALTIME if mode == 'realtime' else CB_PATH_MONITORED_WHODATA

    result = wazuh_log_monitor.start(timeout=TIMEOUT,
                                     callback=generate_monitoring_callback(monitoring_regex),
                                     error_message=ERR_MSG_MONITORING_PATH).result()
    create_multiple_files(get_configuration)
    # Create files to read max_eps files with added events
    n_results = max_eps * 3
    result = wazuh_log_monitor.start(timeout=TIMEOUT,
                                     accum_results=n_results,
                                     callback=callback_integrity_message,
                                     error_message=f'Received less results than expected ({n_results})').result()

    counter = Counter([date_time for date_time, _ in result])

    for _, n_occurrences in counter.items():
        assert n_occurrences <= max_eps, f'Sent {n_occurrences} but a maximum of {max_eps} was set'
