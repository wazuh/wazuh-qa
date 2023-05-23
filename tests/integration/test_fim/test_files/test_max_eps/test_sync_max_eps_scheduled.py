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

components:
    - fim

suite: files_max_eps

targets:
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
        scheduled: Implies scheduled scan

    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - fim_max_eps_sync
'''
import os
import pytest
import time

from collections import Counter
from wazuh_testing import logger
from wazuh_testing.tools import PREFIX, LOG_FILE_PATH
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.modules import DATA, TIER1, AGENT, WINDOWS, LINUX
from wazuh_testing.modules.fim import TEST_DIR_1, TEST_DIRECTORIES, YAML_CONF_MAX_EPS_SYNC, SCHEDULED_MODE
from wazuh_testing.modules.fim import FIM_DEFAULT_LOCAL_INTERNAL_OPTIONS as local_internal_options
from wazuh_testing.modules.fim.event_monitor import (callback_detect_integrity_check_global,
                                                     callback_integrity_sync_message, ERR_MSG_INTEGRITY_CONTROL_MSG,
                                                     ERR_MSG_MULTIPLE_FILES_CREATION)
from wazuh_testing.tools.file import delete_path_recursively, write_file
from wazuh_testing.modules.fim.utils import generate_params


# Marks
pytestmark = [TIER1, AGENT, WINDOWS, LINUX]

# Variables
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), DATA)
configurations_path = os.path.join(test_data_path, YAML_CONF_MAX_EPS_SYNC)

test_directory = os.path.join(PREFIX, TEST_DIR_1)
conf_params = {TEST_DIRECTORIES: test_directory}


TIMEOUT_CHECK_INTEGRATY_START = 30
TIMEOUT_CHECK_EACH_INTEGRITY_MSG = 90

# Configurations

# Test with the minimum, and the default value
eps_values = ['1', '100']

parameters, metadata = generate_params(extra_params=conf_params,
                                       modes=[SCHEDULED_MODE],
                                       apply_to_all=({'MAX_EPS': eps_value} for eps_value in eps_values))
configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)
configuration_ids = [f"{x['fim_mode']}_mode_{x['max_eps']}_max_eps" for x in metadata]


# Fixtures
@pytest.fixture(scope='module', params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.fixture(scope='module')
def create_multiple_files(get_configuration):
    """Create multiple files of a specific type."""
    max_eps = get_configuration['metadata']['max_eps']
    mode = get_configuration['metadata']['fim_mode']
    os.makedirs(test_directory, exist_ok=True, mode=0o777)
    try:
        for i in range(int(max_eps) + 5):
            file_name = f'file{i}_to_max_eps_{max_eps}_{mode}_mode{time.time()}'
            path = os.path.join(test_directory, file_name)
            write_file(path)
    except OSError:
        logger.info(ERR_MSG_MULTIPLE_FILES_CREATION)


# Tests

def test_max_eps_sync_valid_within_range(configure_local_internal_options_module, get_configuration,
                                         create_multiple_files, configure_environment, restart_wazuh):
    '''
    description: Check if the 'wazuh-syscheckd' daemon applies the limit set in the 'max_eps' tag when
                 a lot of synchronization events are generated. For this purpose, the test will monitor
                 a folder and create multiple testing files in it. Once FIM is started, it will wait for
                 the agent to connect to the manager and generate an integrity message, for that reason
                 this test applies to scheduled mode. Then, the test will collect FIM 'integrity' events
                 generated and check if the number of events matches the testing files created.
                 Finally, it will verify the limit of events per second (eps)
                 is not exceeded by checking the creation time of the testing files.

    wazuh_min_version: 4.2.0

    tier: 1

    parameters:
        - configure_local_internal_options_module:
            type: fixture
            brief: Configure the Wazuh local internal options.
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - create_multiple_file:
            type: fixture
            brief: Create the testing files to be monitored.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - restart_wazuh:
            type: fixture
            brief: Clear the 'ossec.log' file and start a new monitor.

    assertions:
        - Verify that FIM 'integrity' events are generated for each testing file created.
        - Verify that the eps limit set in the 'max_eps' tag has not been exceeded at generating FIM events.

    input_description: A test case (max_eps_synchronization) is contained in external YAML file
                       (wazuh_sync_conf_max_eps.yaml) which includes configuration settings for
                       the 'wazuh-syscheckd' daemon and, these are combined with the
                       testing directories to be monitored defined in the module.
    expected_output:
        - r'.*Sending integrity control message'

    tags:
        - scheduled
        - realtime
        - who_data
    '''
    try:
        max_eps = int(get_configuration['metadata']['max_eps'])

        # Find integrity start before attempting to read max_eps.
        wazuh_log_monitor.start(timeout=TIMEOUT_CHECK_INTEGRATY_START,
                                callback=callback_detect_integrity_check_global,
                                error_message=ERR_MSG_INTEGRITY_CONTROL_MSG).result()

        # Find integrity message for each file created after read max_eps.
        total_file_created = max_eps + 5
        result = wazuh_log_monitor.start(timeout=TIMEOUT_CHECK_EACH_INTEGRITY_MSG, accum_results=total_file_created,
                                         callback=callback_integrity_sync_message,
                                         error_message=f'Received less results than expected\
                                                        ({total_file_created})').result()
        # Collect by time received the messages.
        counter = Counter([date_time for date_time, _ in result])

        # Check the number of occurrences of received messages by time.
        for _, total_occurrences in counter.items():
            assert total_occurrences <= max_eps, f'Sent {total_occurrences} but a maximum of {max_eps} was set'
    finally:
        # Delete all files created.
        delete_path_recursively(test_directory)
