'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check if the 'wazuh-syscheckd' and 'auditd' daemons work together properly.
       In particular, it will be verified that when the 'audit' rules of a directory monitored
       in 'who-data' mode are manipulated multiple times, they switch to being monitored in the
       'realtime' mode. The 'who-data' feature of the of the File Integrity Monitoring (FIM) system uses
       the Linux Audit subsystem to get the information about who made the changes in a monitored directory.
       These changes produce audit events that are processed by 'syscheck' and reported to the manager.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured files
       for changes to the checksums, permissions, and ownership.

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

references:
    - https://man7.org/linux/man-pages/man8/auditd.8.html
    - https://documentation.wazuh.com/current/user-manual/capabilities/auditing-whodata/who-linux.html
    - https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html

pytest_args:
    - fim_mode:
        realtime: Enable real-time monitoring on Linux (using the 'inotify' system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the 'who-data' information.
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - fim_audit
'''
import os
import subprocess

import pytest
import wazuh_testing.fim as fim
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=1)]

# Variables

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
test_directories = [os.path.join('/', 'testdir1'), os.path.join('/', 'testdir2'), os.path.join('/', 'testdir3')]
testdir1, testdir2, testdir3 = test_directories

wazuh_log_monitor = FileMonitor(fim.LOG_FILE_PATH)

# Configurations

configurations = load_wazuh_configurations(configurations_path, __name__)


# Fixture

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Test

@pytest.mark.xfail(reason="It will be blocked by #2174, when it was solve we can enable again this test")
@pytest.mark.parametrize('tags_to_apply, folder, audit_key', [
    ({'config1'}, '/testdir2', 'wazuh_fim')
])
def test_remove_rule_five_times(tags_to_apply, folder, audit_key,
                                get_configuration, configure_environment, restart_syscheckd, wait_for_fim_start):
    '''
    description: Check if FIM stops monitoring with 'whodata' when at least five manipulations
                 in the 'audit' rules have been done by a user. For this purpose, the test
                 will monitor a folder using 'who-data'. Once FIM starts, the test will modify
                 five times the 'audit' rules and, finally it will wait until the monitored
                 directory using 'whodata' is monitored with 'realtime' verifying that
                 the proper FIM events are generated.

    wazuh_min_version: 4.2.0

    parameters:
        - tags_to_apply:
            type: set
            brief: Run test if match with a configuration identifier, skip otherwise.
        - audit_key:
            type: str
            brief: Name of the configured audit key.
        - folder:
            type: str
            brief: Path to the testing directory whose rule will be removed.
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
        - Verify that FIM switches the monitoring mode of the testing directory
          from 'whodata' to 'realtime' when an user edits the 'audit' rules.

    input_description: A test case (config1) is contained in external YAML file (wazuh_conf.yaml)
                       which includes configuration settings for the 'wazuh-syscheckd' daemon and, it
                       is combined with the testing directories to be monitored defined in this module.

    expected_output:
        - r'Detected Audit rules manipulation'
        - r'.*Deleting Audit rules'

    tags:
        - audit-rules
        - who-data
    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])

    for _ in range(0, 5):
        subprocess.run(["auditctl", "-W", folder, "-p", "wa", "-k", audit_key], check=True)
        wazuh_log_monitor.start(timeout=20, callback=fim.callback_audit_rules_manipulation,
                                error_message='Did not receive expected '
                                              '"Detected Audit rules manipulation" event')

    wazuh_log_monitor.start(timeout=20, callback=fim.callback_audit_deleting_rule,
                            error_message='Did not receive expected "Deleting Audit rules" event')
