'''
copyright: Copyright (C) 2015-2023, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check if the 'wazuh-syscheckd' and 'auditd' daemons work together properly.
       In particular, it will be verified that when there is no 'auditd' package installed on
       the system, the directories monitored with 'who-data' mode are monitored with 'realtime'.
       The 'who-data' feature of the of the File Integrity Monitoring (FIM) system uses
       the Linux Audit subsystem to get the information about who made the changes in a monitored directory.
       These changes produce audit events that are processed by 'syscheck' and reported to the manager.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured files
       for changes to the checksums, permissions, and ownership.

components:
    - fim

suite: files_audit

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
import re
import subprocess

import pytest
from distro import id

from wazuh_testing.tools import PREFIX, LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_configuration_template, get_test_cases_data
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.utils import retry
from wazuh_testing.modules.fim import TEST_DIR_1
from wazuh_testing.modules.fim.event_monitor import callback_audit_cannot_start
from wazuh_testing.modules.fim import FIM_DEFAULT_LOCAL_INTERNAL_OPTIONS as local_internal_options


# Marks
pytestmark = [pytest.mark.linux, pytest.mark.tier(level=1)]

# Reference paths
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, 'configuration_template')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases')

# Configuration and cases data
test_cases_path = os.path.join(TEST_CASES_PATH, 'cases_remove_audit.yaml')
configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_remove_audit.yaml')

# Test configurations
configuration_parameters, configuration_metadata, test_case_ids = get_test_cases_data(test_cases_path)
configurations = load_configuration_template(configurations_path, configuration_parameters, configuration_metadata)

# Variables
test_directories = [os.path.join(PREFIX, TEST_DIR_1)]


# Function
@retry(subprocess.CalledProcessError, attempts=5, delay=10)
def run_process(command_list):
    """Execute the command_list command

    Args:
        command_list (list): Command to be executed.

    Returns:
        subprocess.CompletedProcess: Command executed.
    """
    return subprocess.run(command_list, check=True)


# Fixtures
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
    process = run_process([package_management, "remove", audit, option])

    yield

    # Install audit and start the service
    process = run_process([package_management, "install", audit, option])
    process = run_process(["service", "auditd", "start"])


# Test
@pytest.mark.parametrize('test_folders', [test_directories], scope="module", ids='')
@pytest.mark.parametrize('configuration, metadata', zip(configurations, configuration_metadata), ids=test_case_ids)
def test_move_folders_to_realtime(configuration, metadata, set_wazuh_configuration, create_monitored_folders,
                                  configure_local_internal_options_function, uninstall_install_audit,
                                  restart_syscheck_function):
    '''
    description: Check if FIM switches the monitoring mode of the testing directories from 'who-data'
                 to 'realtime' when the 'auditd' package is not installed. For this purpose, the test
                 will monitor several folders using 'whodata' and uninstall the 'authd' package.
                 Once FIM starts, it will wait until the monitored directories using 'whodata'
                 are monitored with 'realtime' verifying that the proper FIM events are generated.
                 Finally, the test will install the 'auditd' package again.


    test_phases:
        - setup:
            - Apply ossec.conf configuration changes according to the configuration template and use case.
            - Apply custom settings in local_internal_options.conf.
            - Remove auditd
            - Truncate wazuh logs.
            - Restart wazuh-syscheck daemon to apply configuration changes.
        - test:
            - Check that whodata cannot start and monitoring of configured folder is changed to realtime mode.
        - teardown:
            - Install auditd
            - Restore initial configuration, both ossec.conf and local_internal_options.conf.

    wazuh_min_version: 4.2.0

    tier: 1

    parameters:
        - configuration:
            type: dict
            brief: Configuration values for ossec.conf.
        - metadata:
            type: dict
            brief: Test case data.
        - set_wazuh_configuration:
            type: fixture
            brief: Set ossec.conf configuration.
        - create_monitored_folders_module
            type: fixture
            brief: Create folders to be monitored, delete after test.
        - configure_local_internal_options_function:
            type: fixture
            brief: Set local_internal_options.conf file.
        - uninstall_install_audit:
            type: fixture
            brief: Uninstall 'auditd' before the test and install it again after the test run.
        - restart_syscheck_function:
            type: fixture
            brief: restart syscheckd daemon, and truncate the ossec.log.

    assertions:
        - Verify that FIM switches the monitoring mode of the testing directories from 'whodata' to 'realtime'
          if the 'authd' package is not installed.

    input_description: A test case is contained in external YAML file (configuration_remove_audit.yaml)
                       which includes configuration settings for the 'wazuh-syscheckd' daemon
                       and, it is combined with the testing directories to be monitored
                       defined in this module.

    expected_output:
        - r'.*Who-data engine could not start. Switching who-data to real-time.'

    tags:
        - realtime
        - who_data
    '''
    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
    wazuh_log_monitor.start(timeout=20, callback=callback_audit_cannot_start,
                            error_message='Did not receive expected "Who-data engine could not start. '
                                          'Switching who-data to real-time" event')
