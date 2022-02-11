'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts
       when these files are modified. Specifically, these tests will verify that FIM limits
       the maximum number of files scanned per second, set in the 'max_files_per_second' tag.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured
       files for changes to the checksums, permissions, and ownership.

tier: 1

modules:
    - fim

components:
    - agent
    - manager

daemons:
    - wazuh-syscheckd

os_platform:
    - linux
    - macos
    - solaris

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
    - macOS Catalina
    - Solaris 10
    - Solaris 11

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html#max-files-per-second
    - https://en.wikipedia.org/wiki/Inode

pytest_args:
    - fim_mode:
        realtime: Enable real-time monitoring on Linux (using the 'inotify' system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the 'who-data' information.
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - fim_max_files_per_second
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

@pytest.mark.skip(reason="It will be blocked by #2174, when it was solve we can enable again this test")
@pytest.mark.parametrize('inode_collision', [
                         (False),
                         pytest.param(True, marks=(pytest.mark.linux, pytest.mark.darwin, pytest.mark.sunos5))
                         ])
def test_max_files_per_second(inode_collision, get_configuration, configure_environment, restart_syscheckd,
                              wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon sleeps to limit the file scanning frequency when
                 the 'max_files_per_second' option is enabled. For this purpose, after the 'baseline' is
                 generated, the test will create testing files inside a monitored folder. Then, if the
                 'max_files_per_second' tag is set (its value is != 0), it will verify that FIM 'sleep'
                 events are generated. Finally, the test will check the inode collision algorithm by
                 removing the testing files and creating them again, verifying that FIM 'sleep' events
                 are generated.

    wazuh_min_version: 4.2.0

    parameters:
        - inode_collision:
            type: bool
            brief: True if the limit, while running inode collisions, should be checked. False otherwise.
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
        - Verify that FIM sleeps once the maximum number of files scanned per second is reached.
        - Verify that FIM does not sleep if the 'max_files_per_second' option is disabled.
        - Verify the file scanning limit is also applied to the inode collision algorithm.

    input_description: A test case (max_files_per_second) is contained in external YAML file (wazuh_conf.yaml)
                       which includes configuration settings for the 'wazuh-syscheckd' daemon and, these are
                       combined with the testing directories to be monitored defined in the module.

    expected_output:
        - r'.*Maximum number of files read per second reached, sleeping'
        - r'.*Sending FIM event: (.+)$' ('added' events)

    tags:
        - realtime
        - scheduled
        - time_travel
        - who_data
    '''
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