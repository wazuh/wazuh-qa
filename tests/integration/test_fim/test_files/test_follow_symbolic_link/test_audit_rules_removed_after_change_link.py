# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
from time import sleep

import pytest

pytestmark = [pytest.mark.linux, pytest.mark.sunos5, pytest.mark.darwin, pytest.mark.tier(level=1)]

from test_fim.test_files.test_follow_symbolic_link.common import configurations_path, testdir1, \
    modify_symlink, testdir_link, testdir_target, testdir_not_target, \
    test_directories

from wazuh_testing.fim import generate_params, create_file, REGULAR, SYMLINK, callback_detect_event, \
                              LOG_FILE_PATH, change_internal_options
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing import global_parameters
import re

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

# Variables

fname = "testfile"
symlink_root_path = "/"
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


def callback_get_audit_reload_paths(line):
    """
    Callback that gets the path of the reloaded rules and the number of rules that has been reloaded
    """
    match = re.match(r'.*Audit rule loaded: -w (.+) -p', line)
    if match:
        return match.group(1)

    match = re.match(r'.*Audit rules reloaded. Rules loaded: (.+)', line)
    if match:
        return int(match.group(1))

    return None


def get_reloaded_rules(monitor, sleep_time=30):
    """
    Functions that gets the path of all the rules that has been reloaded.
    Parameters
    ----------
    monitor: FileMonitor
        FileMonitor object to monitor the Wazuh log
    sleep_time: int
        Time to sleep before looking for the logs. Defaults to 30 seconds in the wazuh code.
    """
    sleep(sleep_time)
    ret = None
    path_list = list()

    while not isinstance(ret, int):
        ret = monitor.start(timeout=global_parameters.default_timeout, callback=callback_get_audit_reload_paths,
                            error_message='Did not receive expected "Audit rule loaded: -w ... -p" event').result()
        if isinstance(ret, str):
            path_list.append(ret)

    return path_list


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
    rules_paths = get_reloaded_rules(wazuh_log_monitor)

    create_file(REGULAR, new_target, file_name)
    ev = wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_event,
                                 error_message='Did not receive expected "Sending FIM event: ..." event').result()

    assert ev['data']['type'] == 'added' and ev['data']['path'] == os.path.join(new_target, file_name)

    assert replaced_target not in rules_paths, f'The audit rule has been reloaded for {replaced_target}'
