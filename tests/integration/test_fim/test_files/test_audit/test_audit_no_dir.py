'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check if the File Integrity Monitoring (FIM) system does not add 'audit' rules for
       non-existing directories. The 'who-data' feature of the FIM system uses the Linux Audit subsystem
       to get the information about who made the changes in a monitored directory. These changes produce
       audit events that are processed by 'syscheck' and reported to the manager. The FIM capability
       is managed by the 'wazuh-syscheckd' daemon, which checks configured files for changes
       to the checksums, permissions, and ownership.

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
import shutil
import sys

import pytest
import wazuh_testing.fim as fim
from wazuh_testing import global_parameters
from wazuh_testing.tools import PREFIX, ALERT_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=1)]

# Variables

test_directories = []
testdir = os.path.join(PREFIX, 'testdir')
filename = 'testfile'
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
wazuh_log_monitor = FileMonitor(fim.LOG_FILE_PATH)
wazuh_alert_monitor = FileMonitor(ALERT_FILE_PATH)

# Configurations

p, m = fim.generate_params(extra_params={'TEST_DIRECTORIES': testdir}, modes=['whodata'])
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Functions

def extra_configuration_before_yield():
    # Check that the directory does not exist and that Auditd is active.
    assert not os.path.exists(testdir), 'Directory should not exist before test'

    if sys.platform != 'win32':
        status = os.system('systemctl is-active --quiet auditd')
        assert status == 0, 'Audit daemon is not active before performing the test.'


def extra_configuration_after_yield():
    # Remove directory after test
    shutil.rmtree(testdir, ignore_errors=True)


@pytest.mark.xfail(reason="It will be blocked by #2174, when it was solve we can enable again this test")
@pytest.mark.parametrize('tags_to_apply', [
    {'audit_no_dir'}
])
def test_audit_no_dir(tags_to_apply, get_configuration, configure_environment, restart_syscheckd):
    '''
    description: Monitor non-existent directory with 'who-data' and check that it is added
                 to the rules after creating it. For this purpose, the test will monitor
                 a non-existing folder using 'who-data'. Once FIM starts, the test
                 will check that the audit rule is not added. Then, it will create
                 the folder and wait until the rule is added again.
                 The audit thread runs always a directory that is configured to be monitored
                 in 'who-data' mode. Does not matter if it exists at start-up or not. Once that
                 thread is up, the audit rules are reloaded every 30 seconds (not configurable),
                 so when the directory is created, it starts to be monitored.

    wazuh_min_version: 4.2.0

    parameters:
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
            brief: Clear the 'ossec.log' file and start a new monitor.

    assertions:
        - Verify that FIM does not add rules for non-existing directories.
        - Verify that FIM is able to monitor a folder after it's creation.

    input_description: A test case (audit_no_dir) is contained in external YAML file (wazuh_conf.yaml)
                       which includes configuration settings for the 'wazuh-syscheckd' daemon
                       and, it is combined with the testing directories to be monitored
                       defined in this module.

    expected_output:
        - r'.*Unable to add audit rule for'
        - r'.*Added audit rule for monitoring directory'

    tags:
        - audit-rules
        - who-data
    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])

    # Assert message is generated: Unable to add audit rule for ....
    result = wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=fim.callback_audit_unable_dir,
                                     error_message='Did not receive message "Unable to add audit rule for ..."'
                                     ).result()
    assert result == testdir, f'{testdir} not in "Unable to add audit rule for {result}" message'

    # Create the directory and verify that it is added to the audit rules. It is checked every 30 seconds.
    os.makedirs(testdir)
    fim.wait_for_audit(True, wazuh_log_monitor)
    result = wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=fim.callback_audit_added_rule,
                                     error_message='Folders were not added to Audit rules list').result()
    assert result == testdir, f'{testdir} not in "Added audit rule for monitoring directory: {result}" message'
