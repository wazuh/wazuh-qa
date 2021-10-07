'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when these
       files are modified. Specifically, these tests will check the 'prelink' program is installed on
       the system to prevent prelinking from creating false positives running it before FIM scanning.
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

os_version:
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
    - fim_nodiff
'''
import os
import subprocess

import distro
import pytest
from wazuh_testing.fim import LOG_FILE_PATH, generate_params
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=1)]

# variables

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
test_directories = [os.path.join('/', 'testdir1')]
force_restart_after_restoring = True

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

# configurations

prefilter = '/usr/sbin/prelink -y'
conf_params, conf_metadata = generate_params(extra_params={'PREFILTER_CMD': prefilter})

configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=conf_params,
                                           metadata=conf_metadata
                                           )


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.fixture(scope='session')
def check_prelink():
    # Call script to install prelink if it is not installed
    path = os.path.dirname(os.path.abspath(__file__))
    dist_list = ['centos', 'fedora', 'rhel']
    dist = 'ubuntu' if distro.id() not in dist_list else 'fedora'
    subprocess.call([f'{path}/data/install_prelink.sh', dist])


# tests


@pytest.mark.parametrize('tags_to_apply', [
    ({'prefilter_cmd'})
])
def test_prefilter_cmd(tags_to_apply, get_configuration, configure_environment, check_prelink, restart_syscheckd,
                       wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' detects the 'prelink' program installed on the system and runs it
                 using the command defined in the 'prefilter_cmd' tag. For this purpose, the test will monitor
                 a testing directory and run a bash script to check if the 'prelink' program is installed and
                 install it if necessary. Finally, it will verify that the command to run the 'prelink' program
                 is defined in the configuration.

    wazuh_min_version: 4.2.0

    parameters:
        - tags_to_apply:
            type: set
            brief: Run test if matches with a configuration identifier, skip otherwise.
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - check_prelink:
            type: fixture
            brief: Call script to install 'prelink' if it is not installed.
        - restart_syscheckd:
            type: fixture
            brief: Clear the 'ossec.log' file and start a new monitor.
        - wait_for_fim_start:
            type: fixture
            brief: Wait for realtime start, whodata start, or end of initial FIM scan.

    assertions:
        - Verify that the 'prelink' program is installed on the system.

    input_description: A test case (prefilter_cmd) is contained in external YAML file (wazuh_conf.yaml)
                       which includes configuration settings for the 'wazuh-syscheckd' daemon and, these
                       are combined with the testing directory to be monitored defined in the module.
                       Also, a bash script (install_prelink.sh) is included to check if
                       the 'prelink' program is installed and install it if necessary.

    expected_output:
        - The path of the 'prelink' program.

    tags:
        - prelink
    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])

    if get_configuration['metadata']['prefilter_cmd'] == '/usr/sbin/prelink -y':
        prelink = get_configuration['metadata']['prefilter_cmd'].split(' ')[0]
        assert os.path.exists(prelink), f'Prelink is not installed'
