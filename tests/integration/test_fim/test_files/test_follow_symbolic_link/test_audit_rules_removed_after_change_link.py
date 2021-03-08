# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
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
    """ Test that checks if the audit rules are removed when the symlink target's is changed.

    Args:
        replaced_target (str): Directory where the link is pointing.
        new_target (str): Directory where the link will be pointed after it's updated.
        file_name (str): Name of the file that will be created inside the folders.
        tags_to_apply (set): Run test if matches with a configuration identifier, skip otherwise.
        get_configuration (fixture): Gets the current configuration of the test.
        configure_environment (fixture): Configure the environment for the execution of the test.
        restart_syscheckd (fixture): Restarts syscheck.
        wait_for_fim_start (fixture): Waits until the first FIM scan is completed.

    Raises:
        TimeoutError: If an expected event couldn't be captured.
        ValueError: If the event type isn't added or if the audit rule for ``replaced_target`` isn't removed.

    """
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
