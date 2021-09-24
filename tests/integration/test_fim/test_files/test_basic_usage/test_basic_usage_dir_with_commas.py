'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check if the File Integrity Monitoring (`FIM`) system watches selected files
       and triggering alerts when these files are modified. Specifically, they will check if `FIM` events
       are generated on a monitored folder whose name contains commas.
       The FIM capability is managed by the `wazuh-syscheckd` daemon, which checks configured files
       for changes to the checksums, permissions, and ownership.

tier: 2

modules:
    - fim

components:
    - agent

daemons:
    - wazuh-agentd
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
    - Windows Server 2016
    - Windows server 2012
    - Windows server 2003

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html

pytest_args:
    - fim_mode:
        realtime: Enable real-time monitoring on Linux (using the `inotify` system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the `who-data` information.

tags:
    - fim
'''
import os

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, generate_params, regular_file_cud
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks
pytestmark = pytest.mark.tier(level=2)

# Variables and configuration
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

test_directories = [os.path.join(PREFIX, 'test,dir1'),
                    os.path.join(PREFIX, 'testdir2,')]
dir1, dir2 = test_directories

config_dirs = [os.path.join(PREFIX, 'test\\,dir1'),
               os.path.join(PREFIX, 'testdir2\\,')]
config_dirs = "{1}{0}{2}".format(", ", config_dirs[0], config_dirs[1])

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')

conf_params = {'TEST_DIRECTORIES': config_dirs, 'MODULE_NAME': __name__}
p, m = generate_params(extra_params=conf_params)

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
def test_directories_with_commas(directory, get_configuration, put_env_variables, configure_environment,
                                 restart_syscheckd, wait_for_fim_start):
    '''
    description: Check if the `wazuh-syscheckd` daemon generates `FIM` events from monitoring folders
                 whose name contains commas. For this purpose, the test will monitor a testing folder
                 using the `scheduled` monitoring mode, and create the testing files inside it.
                 Then, perform CUD (creation, update, and delete) operations and finally verify that
                 the `FIM` events are generated correctly. 

    wazuh_min_version: 4.2

    parameters:
        - directory:
            type: str
            brief: Path to the monitored testing directory.
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
            brief: Clear the `ossec.log` file and start a new monitor.
        - wait_for_fim_start:
            type: fixture
            brief: Wait for realtime start, whodata start, or end of initial FIM scan.

    assertions:
        - Verify that `FIM` events are generated on a monitored folder whose name contains commas.

    input_description: A test case is contained in external `YAML` file (wazuh_conf.yaml) which includes
                       configuration settings for the `wazuh-syscheckd` daemon and, it is combined with
                       the testing directories to be monitored defined in this module.

    expected_output:
        - Multiple `FIM` events logs of the monitored directories.

    tags:
        - scheduled
        - time_travel
    '''
    check_apply_test({'ossec_conf'}, get_configuration['tags'])

    regular_file_cud(directory, wazuh_log_monitor, file_list=["testing_env_variables"],
                     min_timeout=global_parameters.default_timeout,
                     time_travel=get_configuration['metadata']['fim_mode'] == 'scheduled')
