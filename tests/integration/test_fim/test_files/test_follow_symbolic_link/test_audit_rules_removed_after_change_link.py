# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import subprocess

import pytest


from wazuh_testing.fim import generate_params, create_file, REGULAR, SYMLINK, callback_detect_event, \
                              LOG_FILE_PATH, change_internal_options
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing import global_parameters
from wazuh_testing.tools import PREFIX

from test_fim.test_files.test_follow_symbolic_link.common import configurations_path, testdir1, \
    modify_symlink, testdir_not_target, wait_for_audit, wait_for_symlink_check
# noinspection PyUnresolvedReferences
from test_fim.test_files.test_follow_symbolic_link.common import test_directories

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=1)]

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

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

conf_params, conf_metadata = generate_params(extra_params=param_dir, modes=['whodata'])
configurations = load_wazuh_configurations(configurations_path, __name__, params=conf_params, metadata=conf_metadata)

# Functions


def extra_configuration_before_yield():
    """
    Setup the symlink to one folder
    """
    # Symlink pointing to testdir1
    create_file(SYMLINK, symlink_root_path, symlink_name, target=testdir1)
    # Set symlink_scan_interval to a given value
    change_internal_options(param='syscheck.symlink_scan_interval', value=link_interval)


def extra_configuration_after_yield():
    """
    Setup the symlink to one folder
    """
    # Symlink pointing to testdir1
    os.remove(symlink_path)
    change_internal_options(param='syscheck.symlink_scan_interval', value=600)


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
    """
    Parameters
    ----------
    main_folder : str
        Directory that is being pointed at or contains the pointed file.
    aux_folder : str
        Directory that will be pointed at or will contain the future pointed file.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])
    create_file(REGULAR, replaced_target, file_name)
    ev = wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_event,
                                 error_message='Did not receive expected "Sending FIM event: ..." event').result()

    assert ev['data']['type'] == 'added' and ev['data']['path'] == os.path.join(replaced_target, file_name)

    # Change the target of the symlink and expect events while there's no syscheck scan

    modify_symlink(new_target, symlink_path)
    wait_for_symlink_check(wazuh_log_monitor)
    wait_for_audit(True, wazuh_log_monitor)

    rules_paths = str(subprocess.check_output(['auditctl', '-l']))
    create_file(REGULAR, new_target, file_name)
    ev = wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_event,
                                 error_message='Did not receive expected "Sending FIM event: ..." event').result()

    assert ev['data']['type'] == 'added' and ev['data']['path'] == os.path.join(new_target, file_name)

    assert replaced_target not in rules_paths, f'The audit rule has been reloaded for {replaced_target}'
