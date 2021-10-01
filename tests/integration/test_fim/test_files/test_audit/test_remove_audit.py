'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check if the `wazuh-syscheckd` and `auditd` daemons work together properly.
       In particular, it will be verified that when there is no `auditd` package installed on
       the system, the directories monitored with `who-data` mode are monitored with `realtime`.
       The `who-data` feature of the of the File Integrity Monitoring (`FIM`) system uses
       the Linux Audit subsystem to get the information about who made the changes in a monitored directory.
       These changes produce audit events that are processed by `syscheck` and reported to the manager.
       The `FIM` capability is managed by the `wazuh-syscheckd` daemon, which checks configured files
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
        realtime: Enable real-time monitoring on Linux (using the `inotify` system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the `who-data` information.

tags:
    - fim
    - auditd
'''
import os
import re
import subprocess

import pytest
import wazuh_testing.fim as fim
from distro import id
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


# Fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.fixture(scope='module')
def uninstall_install_audit():
    """Uninstall auditd before test and install after test"""

    # Check distro
    linux_distro = id()

    if re.match(linux_distro, "centos"):
        package_management = "yum"
        audit = "audit"
        option = "--assumeyes"
    elif re.match(linux_distro, "ubuntu") or re.match(linux_distro, "debian"):
        package_management = "apt-get"
        audit = "auditd"
        option = "--yes"
    else:
        raise ValueError(f"Linux distro ({linux_distro}) not supported for uninstall/install audit")

    # Uninstall audit
    process = subprocess.run([package_management, "remove", audit, option], check=True)

    yield

    # Install audit and start the service
    process = subprocess.run([package_management, "install", audit, option], check=True)
    process = subprocess.run(["service", "auditd", "start"], check=True)


# Test

@pytest.mark.parametrize('tags_to_apply', [
    {'config1'}
])
def test_move_folders_to_realtime(tags_to_apply, get_configuration, uninstall_install_audit,
                                  configure_environment, restart_syscheckd):
    '''
    description: Check if `FIM` switches the monitoring mode of the testing directories from `who-data`
                 to `realtime` when the `auditd` package is not installed. For this purpose, the test
                 will monitor several folders using `whodata` and uninstall the `authd` package.
                 Once `FIM` starts, it will wait until the monitored directories using `whodata`
                 are monitored with `realtime` verifying that the proper `FIM` events are generated.
                 Finally, the test will install the `auditd` package again.

    wazuh_min_version: 4.2

    parameters:
        - tags_to_apply:
            type: set
            brief: Run test if match with a configuration identifier, skip otherwise.
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - uninstall_install_audit:
            type: fixture
            brief: Uninstall `auditd` before the test and install it again after the test run.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - restart_syscheckd:
            type: fixture
            brief: Clear the `ossec.log` file and start a new monitor.

    assertions:
        - Verify that `FIM` switches the monitoring mode of the testing directories from `whodata` to `realtime`
          if the `authd` package is not installed.

    input_description: A test case (config1) is contained in external `YAML` file (wazuh_conf.yaml)
                       which includes configuration settings for the `wazuh-syscheckd` daemon
                       and, it is combined with the testing directories to be monitored
                       defined in this module.

    expected_output:
        - r'.*Who-data engine could not start. Switching who-data to real-time.'

    tags:
        - realtime
        - who-data
    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])

    wazuh_log_monitor.start(timeout=20, callback=fim.callback_audit_cannot_start,
                            error_message='Did not receive expected "Who-data engine could not start. '
                                          'Switching who-data to real-time" event')
