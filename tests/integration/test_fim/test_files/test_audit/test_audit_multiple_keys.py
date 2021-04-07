# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2


import os
import subprocess

import pytest
import wazuh_testing.fim as fim

from wazuh_testing import global_parameters
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=1)]

# Variables

monitored_test_dir = os.path.join(PREFIX, 'monitored_test_dir')
non_monitored_test_dir = os.path.join(PREFIX, 'non_monitored_test_dir')
custom_keys = ['key1', 'key2']
param_list = []

param_list = ' '.join([f'-k {key}' for key in custom_keys])

test_directories = [monitored_test_dir, non_monitored_test_dir]
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf_multiple_audit_keys.yaml')

wazuh_log_monitor = FileMonitor(fim.LOG_FILE_PATH)

# Configurations

config_params, config_metadata = fim.generate_params(extra_params={'MONITORED_DIR': monitored_test_dir,
                                                     'AUDIT_KEYS': ','.join(key for key in custom_keys)},
                                                     modes=['whodata'])

configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=config_params, metadata=config_metadata)


def run_audit_command(directory, params='', cmd_type='add'):
    """Function to run auditctl commands.

    Args:
        directory (str): An audit rule will be added or deleted for this directory.
        params (str): Parameters for auditctl.
        cmd_type (str): type of command that will be used.
                        - add to create a new audit rule.
                        - delete to remove an audit rule.
    Raises:
        ValueError: If cmd_type is not add or delete.
    """

    if cmd_type == 'add':
        audit_flag = '-w'
    elif cmd_type == 'delete':
        audit_flag = '-W'
    else:
        raise ValueError("Only add and delete values are allowed")

    command = f"auditctl {audit_flag} {directory} -p wa {params}"
    subprocess.run(command.split())


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Functions

def extra_configuration_before_yield():
    # Create the custom audit rules for the non monitored directory
    run_audit_command(directory=non_monitored_test_dir, params=param_list, cmd_type='add')
    # Remove audit rule that FIM configures for each monitored directory
    run_audit_command(directory=monitored_test_dir, params='-k wazuh_fim', cmd_type='delete')
    # Set the audit rule for the monitored directory with more than one key
    run_audit_command(directory=monitored_test_dir, params='-k wazuh_fim -k "a_random_key"', cmd_type='add')


def extra_configuration_after_yield():
    # Remove the audit rules configured by the test
    run_audit_command(directory=non_monitored_test_dir, params=param_list, cmd_type='delete')
    run_audit_command(directory=monitored_test_dir, params=param_list, cmd_type='delete')


@pytest.mark.parametrize('tags_to_apply', [{'audit_multiple_keys'}])
@pytest.mark.parametrize('directory', [monitored_test_dir, non_monitored_test_dir])
def test_audit_multiple_keys(directory, tags_to_apply, get_configuration, configure_environment, restart_syscheckd,
                             wait_for_fim_start):
    """Checks that FIM correctly handles audit rules with multiple keys.

    Args:
        directory (str): Directory where the changes will be done.
        tags_to_apply (set): Run test if matches with a configuration identifier, skip otherwise.
        get_configuration (fixture): Gets the current configuration of the test.
        configure_environment (fixture): Configure the environment for the execution of the test.
        restart_syscheckd (fixture): Restarts syscheck.
        wait_for_fim_start (fixture): Waits until the first FIM scan is completed.

    Raises:
        TimeoutError: If an expected event couldn't be captured.
        ValueError: If the path of the event is wrong.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])
    # Wait until FIM reloads the audit rules.
    wazuh_log_monitor.start(timeout=35,
                            callback=fim.callback_audit_reloading_rules,
                            accum_results=1,
                            update_position=True,
                            error_message='Did not receive expected "Audit reloading rules ..." event ')

    fim.create_file(fim.REGULAR, directory, "testfile")
    key = wazuh_log_monitor.start(timeout=35,
                                  callback=fim.callback_get_audit_key,
                                  accum_results=1,
                                  update_position=True,
                                  error_message='Did not receive expected "Match audit_key: ..." event ').result()

    if key != 'wazuh_fim':
        assert key in custom_keys, f'{key} not found in {custom_keys}'

    try:
        event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                        callback=fim.callback_detect_event,
                                        accum_results=1,
                                        error_message='Did not receive expected "Sending FIM event..." event '
                                        ).result()

        assert get_configuration['metadata']['monitored_dir'] == directory, 'No events should be detected.'
        event_path = event['data']['path']
        assert directory in event_path, f"Expected path = {directory}, event path = {event_path}"

    except TimeoutError as e:
        # If the directory of the event is monitored, raise the TimeoutError exception
        if get_configuration['metadata']['monitored_dir'] == directory:
            raise e
