'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when these files
       are modified. Specifically, these tests will check if FIM automatically removes the 'audit' rule
       from the target of a monitored 'symbolic link' when the target of that link is replaced.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured
       files for changes to the checksums, permissions, and ownership.

components:
    - fim

suite: files_follow_symbolic_link

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
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html#whodata
    - https://man7.org/linux/man-pages/man8/auditd.8.html

pytest_args:
    - fim_mode:
        realtime: Enable real-time monitoring on Linux (using the 'inotify' system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the 'who-data' information.
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - fim_follow_symbolic_link
    - audit_rules
'''
import os
import subprocess

import pytest
import wazuh_testing.fim as fim

from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing import global_parameters
from wazuh_testing.tools import PREFIX

from test_fim.test_files.test_follow_symbolic_link.common import configurations_path, testdir1, testdir_not_target, \
                                                                 wait_for_symlink_check, modify_symlink
# noinspection PyUnresolvedReferences
from test_fim.test_files.test_follow_symbolic_link.common import test_directories

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=1)]

wazuh_log_monitor = FileMonitor(fim.LOG_FILE_PATH)

# Variables

fname = "testfile"
symlink_root_path = PREFIX
symlink_name = "symlink"
symlink_path = os.path.join(symlink_root_path, symlink_name)
link_interval = 2

param_dir = {
    'FOLLOW_MODE': 'yes',
    'LINK_PATH': symlink_path
}

# Configurations

conf_params, conf_metadata = fim.generate_params(extra_params=param_dir, modes=['whodata'])
configurations = load_wazuh_configurations(configurations_path, __name__, params=conf_params, metadata=conf_metadata)

# Functions


def extra_configuration_before_yield():
    """
    Setup the symlink to one folder
    """
    # Symlink pointing to testdir1
    fim.create_file(fim.SYMLINK, symlink_root_path, symlink_name, target=testdir1)
    # Set symlink_scan_interval to a given value
    fim.change_internal_options(param='syscheck.symlink_scan_interval', value=link_interval)


def extra_configuration_after_yield():
    """
    Setup the symlink to one folder
    """
    # Symlink pointing to testdir1
    os.remove(symlink_path)
    fim.change_internal_options(param='syscheck.symlink_scan_interval', value=600)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests

@pytest.mark.parametrize('replaced_target, new_target, file_name, tags_to_apply', [
                         (testdir1, testdir_not_target, f'{fname}_1', {'check_audit_removed_rules'})
                         ])
def test_audit_rules_removed_after_change_link(replaced_target, new_target, file_name, tags_to_apply,
                                               get_configuration, configure_environment,
                                               restart_syscheckd, wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon removes the 'audit' rules when the target of
                 a monitored symlink is changed. For this purpose, the test will monitor a 'symbolic link'
                 pointing to a directory using the 'whodata' monitoring mode. Once FIM starts, it will create
                 and expect events inside the pointed folder. After the events are processed, the test
                 will change the target of the link to another folder and wait until the thread that checks
                 the 'symbolic links' updates the link's target. Finally, it will generate some events inside
                 the new target and verify that the audit rule of the previous target folder has been
                 removed (via 'auditctl -l').

    wazuh_min_version: 4.2.0

    tier: 1

    parameters:
        - replaced_target:
            type: str
            brief: Directory where the 'symbolic link' is pointing.
        - new_target:
            type: str
            brief: Directory where the 'symbolic link' will be pointed after it is updated.
        - file_name:
            type: str
            brief: Name of the testing file that will be created inside the folders.
        - tags_to_apply:
            type: set
            brief: Run test if matches with a configuration identifier, skip otherwise.
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
        - Verify that FIM events 'added' are generated when creating the testing files.
        - Verify that FIM automatically removes the 'audit' rule from the target of a monitored 'symbolic link'
          when the target of that link is replaced.

    input_description: A test case (check_audit_removed_rules) is contained in external YAML file (wazuh_conf.yaml)
                       which includes configuration settings for the 'wazuh-syscheckd' daemon and, it is
                       combined with the testing directory to be monitored defined in the 'common.py' module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added' events)
        - The 'auditctl -l' command should return the path where the symbolic link finally points.

    tags:
        - realtime
        - who_data
    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])
    fim.create_file(fim.REGULAR, replaced_target, file_name)
    ev = wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=fim.callback_detect_event,
                                 error_message='Did not receive expected "Sending FIM event: ..." event').result()

    assert ev['data']['type'] == 'added' and ev['data']['path'] == os.path.join(replaced_target, file_name)

    # Change the target of the symlink and expect events while there's no syscheck scan

    modify_symlink(new_target, symlink_path)
    wait_for_symlink_check(wazuh_log_monitor)
    fim.wait_for_audit(True, wazuh_log_monitor)

    rules_paths = str(subprocess.check_output(['auditctl', '-l']))
    fim.create_file(fim.REGULAR, new_target, file_name)
    ev = wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=fim.callback_detect_event,
                                 error_message='Did not receive expected "Sending FIM event: ..." event').result()

    assert ev['data']['type'] == 'added' and ev['data']['path'] == os.path.join(new_target, file_name)

    assert replaced_target not in rules_paths, f'The audit rule has been reloaded for {replaced_target}'
