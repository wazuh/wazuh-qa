'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check if the `who-data` feature of the File Integrity Monitoring (`FIM`)
       system works properly. `who-data` information contains the user who made the changes
       on the monitored files and also the program name or process used to carry them out.
       The `FIM` capability is managed by the `wazuh-syscheckd` daemon, which checks
       configured files for changes to the checksums, permissions, and ownership.

tier: 2

modules:
    - fim

components:
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
    - https://documentation.wazuh.com/current/user-manual/capabilities/auditing-whodata/who-linux.html
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
from wazuh_testing.fim import LOG_FILE_PATH, generate_params, callback_real_time_whodata_started
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks


pytestmark = [pytest.mark.linux, pytest.mark.tier(level=2)]

# Variables
test_directories = [os.path.join(PREFIX, 'testdir1')]

directory_str = ','.join(test_directories)
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf_whodata_thread.yaml')
testdir1 = test_directories[0]

# Configurations


p, m = generate_params(extra_params={"TEST_DIRECTORIES": testdir1}, modes=['whodata'])

configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# Fixtures


@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Tests


@pytest.mark.parametrize('whodata_enabled, tags_to_apply', [
    (False, {'whodata_disabled_conf'}),
    (True, {'whodata_enabled_conf'})
])
def test_ambiguous_whodata_thread(whodata_enabled, tags_to_apply, get_configuration, configure_environment,
                                  restart_syscheckd):
    '''
    description: Check if the `wazuh-syscheckd` daemon starts the `whodata` thread when the configuration
                 is ambiguous. For example, when using `whodata` on the same directory using conflicting
                 values (`yes` and `no`). For this purpose, the configuration is applied and it checks
                 that the last value detected for `whodata` in the `ossec.conf` file is the one used.

    wazuh_min_version: 4.2

    parameters:
        - whodata_enabled:
            type: bool
            brief: Who-data status.
        - tags_to_apply:
            type: set
            brief: Run test if match with a configuration identifier, skip otherwise.
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - restart_syscheckd:
            type: fixture
            brief: Clear the `ossec.log` file and start a new monitor.

    assertions:
        - Verify that `whodata` thread is started when the last `whodata` value detected is set to `yes`.
        - Verify that `whodata` thread is not started when the last `whodata` value detected is set to `no`.

    input_description: Two test cases are contained in external `YAML` file (wazuh_conf_whodata_thread.yaml)
                       which includes configuration settings for the `wazuh-syscheckd` daemon and testing
                       directories to monitor.

    expected_output:
        - r'File integrity monitoring real-time Whodata engine started'

    tags:
        - who-data
    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])

    if whodata_enabled:
        wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_real_time_whodata_started,
                                error_message='Did not receive expected '
                                              '"File integrity monitoring real-time Whodata engine started" event')
    else:
        with pytest.raises(TimeoutError):
            wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                    callback=callback_real_time_whodata_started)
            raise AttributeError(f'Unexpected event "File integrity monitoring real-time Whodata engine started"')
