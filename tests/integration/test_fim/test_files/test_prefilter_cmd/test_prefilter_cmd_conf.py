'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when these
       files are modified. Specifically, these tests will check the 'prelink' program is installed on
       the system to prevent prelinking from creating false positives running it before FIM scanning.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured
       files for changes to the checksums, permissions, and ownership.

components:
    - fim

suite: files_prefilter_cmd

targets:
    - agent
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
    - Debian Buster
    - Red Hat 8
    - Ubuntu Focal
    - Ubuntu Bionic

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html#prefilter-cmd
    - https://linux.die.net/man/8/prelink

pytest_args:
    - fim_mode:
        realtime: Enable real-time monitoring on Linux (using the 'inotify' system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the 'who-data' information.
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - fim_prefilter_cmd
'''
import os
import subprocess

import distro
import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, generate_params, check_fim_start, callback_configuration_error
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor

# Marks
pytestmark = [pytest.mark.linux, pytest.mark.tier(level=1), pytest.mark.agent, pytest.mark.server]

# Variables
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_prefilter_cmd_conf.yaml')
test_directories = [os.path.join('/', 'testdir1')]
directory_str = ','.join(test_directories)
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

# Configurations
prefilter = '/usr/sbin/prelink -y'

conf_params, conf_metadata = generate_params(extra_params={'TEST_DIRECTORIES': directory_str,
                                                           'PREFILTER_CMD': prefilter})

configuration_ids = []

for params in conf_params:
    if isinstance(params['FIM_MODE'], dict):
        for fim_mode in params['FIM_MODE'].keys():
            configuration_ids.append(f"prefilter_cmd_conf_{fim_mode}")
    else:
        configuration_ids.append("prefilter_cmd_conf_scheduled")

configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=conf_params,
                                           metadata=conf_metadata
                                           )


# Fixtures
@pytest.fixture(scope='module', params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.fixture(scope='session')
def install_prelink():
    # Call script to install prelink if it is not installed
    path = os.path.dirname(os.path.abspath(__file__))
    dist_list = ['centos', 'fedora', 'rhel']
    dist = 'ubuntu' if distro.id() not in dist_list else 'fedora'
    subprocess.call([f'{path}/data/install_prelink.sh', dist])


# Tests
def test_prefilter_cmd_conf(get_configuration, configure_environment, install_prelink, restart_syscheckd):
    '''
    description: Check if the 'wazuh-syscheckd' detects the 'prelink' program installed on the system and runs it
                 using the command defined in the 'prefilter_cmd' tag. For this purpose, the test will monitor
                 a testing directory and run a bash script to check if the 'prelink' program is installed and
                 install it if necessary. Finally, it will verify that the command to run the 'prelink' program
                 is defined in the configuration.

    wazuh_min_version: 4.2.0

    tier: 1

    parameters:
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - install_prelink:
            type: fixture
            brief: Call script to install 'prelink' if it is not installed.
        - restart_syscheckd:
            type: fixture
            brief: Clear the 'ossec.log' file and start a new monitor.

    assertions:
        - Verify that the 'prelink' program is installed on the system.

    input_description: A test case (prefilter_cmd) is contained in external YAML file (wazuh_prefilter_cmd_conf.yaml)
                       which includes configuration settings for the 'wazuh-syscheckd' daemon and, these are combined
                       with the testing directory to be monitored defined in the module. Also, a bash script
                       (install_prelink.sh) is included to check if the 'prelink' program is installed and install it
                       if necessary.

    expected_output:
        - The path of the 'prelink' program.

    tags:
        - prelink
    '''
    if os.path.exists(prefilter.split()[0]):
        check_fim_start(wazuh_log_monitor)
    else:
        wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_configuration_error,
                                error_message="The expected 'Configuration error at etc/ossec.conf' "
                                              "message has not been produced")
