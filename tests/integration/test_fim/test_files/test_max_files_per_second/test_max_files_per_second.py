'''
copyright:
    Copyright (C) 2015-2021, Wazuh Inc.

    Created by Wazuh, Inc. <info@wazuh.com>.

    This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type:
    integration

brief:
    Check that FIM sleeps for one second when the option max_files_per_second is enabled

tier:
    1

modules:
    - syscheck

components:
    - manager

path:
    tests/integration/test_fim/test_files/test_max_files_per_second/test_max_files_per_second.py

daemons:
    - wazuh-modulesd
    - wazuh-db

os_platform:
    - linux

os_version:
    - Amazon Linux 1
    - Amazon Linux 2
    - Arch Linux
    - CentOS 6
    - CentOS 7
    - CentOS 8
    - Debian Buster
    - Debian Stretch
    - Debian Jessie
    - Debian Wheezy
    - Red Hat 6
    - Red Hat 7
    - Red Hat 8
    - Ubuntu Bionic
    - Ubuntu Trusty
    - Ubuntu Xenial
    - Windows

references:
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html#max-files-per-second

pytest_args:
    - fim_mode:
        value: "realtime"
        brief: Uses real-time file monitoring.
    - fim_mode:
        value: "scheduled"
        brief: Uses scheduled file monitoring.
    - fim_mode:
        value: "whodata"
        brief: Uses whodata file monitoring option.
'''




import os
import pytest

import wazuh_testing.fim as fim
from wazuh_testing import global_parameters
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = pytest.mark.tier(level=1)

# Variables

test_directories = [os.path.join(PREFIX, 'testdir1')]
max_files_per_second = 10
wazuh_log_monitor = FileMonitor(fim.LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
# Values for max_files_per_second option
values = [10, 0]
n_files_to_create = 50
# Configurations

conf_params = {'TEST_DIRECTORIES': test_directories[0]}
p, m = fim.generate_params(extra_params=conf_params, apply_to_all=({'MAX_FILES_PER_SEC': value} for value in values))
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# Fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Tests

@pytest.mark.parametrize('inode_collision', [
                         (False),
                         pytest.param(True, marks=(pytest.mark.linux, pytest.mark.darwin, pytest.mark.sunos5))
                         ])
def test_max_files_per_second(inode_collision, get_configuration, configure_environment, restart_syscheckd,
                              wait_for_fim_start):
    """ 
    description: 
        Check that FIM sleeps for one second when the option max_files_per_second is enabled
    
    parameters:
        - inode_collision:
            type: boolean
            brief: Signals if the test should check the limit while running inode collisions.
        - get_configuration:
            type: fixture
            brief: Gets the current configuration of the test.
        - configure_enviroment:
            type: fixture
            brief: Configure the environment for the execution of the test.
        - restart_syscheckd:
            type: fixture
            brief: Reset ossec.log and start a new monitor.
        - wait_for_fim_start:
            type: fixture
            brief: Wait for realtime start, whodata start or end of initial FIM scan.
    input_description:
        Several files are created, to check if the ammount of files scanned per second is equal to the limit sent on option "max_files_per_second"
    expected_output
        - No output if max_files_per_second=0
        - In case not events are found it Raises:
            TimeoutError: If an expected event couldn't be captured.
    """
    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'

    if inode_collision is True and scheduled is False:
        pytest.skip("realtime and whodata modes do not verify inode collisions")

    # Create the files in an empty folder to check realtime and whodata.
    for i in range(n_files_to_create):
        fim.create_file(fim.REGULAR, test_directories[0], f'test_{i}', content='')

    extra_timeout = n_files_to_create / max_files_per_second
    if inode_collision:
        extra_timeout += global_parameters.default_timeout

    fim.check_time_travel(scheduled, monitor=wazuh_log_monitor,
                          timeout=global_parameters.default_timeout + extra_timeout)

    try:
        wazuh_log_monitor.start(timeout=global_parameters.default_timeout + extra_timeout,
                                callback=fim.callback_detect_max_files_per_second)
    except TimeoutError as e:
        if get_configuration['metadata']['max_files_per_sec'] == 0:
            pass
        else:
            raise e

    if scheduled and get_configuration['metadata']['max_files_per_sec'] != 0:
        # Walk to the end of the scan
        wazuh_log_monitor.start(timeout=global_parameters.default_timeout + extra_timeout,
                                callback=fim.callback_detect_end_scan)

    # Remove all files
    for i in range(n_files_to_create):
        fim.delete_file(test_directories[0], f'test_{i}')

    if inode_collision is True:
        # Create the files again changing all inodes
        fim.create_file(fim.REGULAR, test_directories[0], 'test', content='')
        for i in range(n_files_to_create):
            fim.create_file(fim.REGULAR, test_directories[0], f'test_{i}', content='')

        fim.check_time_travel(scheduled, monitor=wazuh_log_monitor,
                              timeout=global_parameters.default_timeout + extra_timeout)

        try:
            wazuh_log_monitor.start(timeout=global_parameters.default_timeout + extra_timeout,
                                    callback=fim.callback_detect_max_files_per_second)
        except TimeoutError as e:
            if get_configuration['metadata']['max_files_per_sec'] == 0:
                pass
            else:
                raise e
                
