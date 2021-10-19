# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import subprocess

import psutil
import pytest
import wazuh_testing.fim as fim

from wazuh_testing import global_parameters, logger
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.file import truncate_file, remove_file
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.services import control_service, check_daemon_status
from wazuh_testing.tools.utils import retry

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=1)]

# variables

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
test_directories = [os.path.join('/', 'testdir1'), os.path.join('/', 'testdir2'), os.path.join('/', 'testdir3')]
testdir1, testdir2, testdir3 = test_directories

wazuh_log_monitor = FileMonitor(fim.LOG_FILE_PATH)

# configurations

configurations = load_wazuh_configurations(configurations_path, __name__)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests

@pytest.mark.parametrize('tags_to_apply', [
    ({'config1'})
])
def test_audit_health_check(tags_to_apply, get_configuration,
                            configure_environment, restart_syscheckd):
    """Check if the health check is passed.

    Args:
        tags_to_apply (set): Run test if matches with a configuration identifier, skip otherwise.
        get_configuration (fixture): Gets the current configuration of the test.
        configure_environment (fixture): Configure the environment for the execution of the test.
        restart_syscheckd (fixture): Restarts syscheck.
        wait_for_fim_start (fixture): Waits until the first FIM scan is completed.

    Raises:
        TimeoutError: If an expected event couldn't be captured.
    """

    logger.info('Applying the test configuration')
    check_apply_test(tags_to_apply, get_configuration['tags'])

    wazuh_log_monitor.start(timeout=20, callback=fim.callback_audit_health_check,
                            error_message='Health check failed')


@pytest.mark.parametrize('tags_to_apply', [
    ({'config1'})
])
def test_added_rules(tags_to_apply, get_configuration,
                     configure_environment, restart_syscheckd):
    """Check if the specified folders are added to Audit rules list.

    Args:
        tags_to_apply (set): Run test if matches with a configuration identifier, skip otherwise.
        get_configuration (fixture): Gets the current configuration of the test.
        configure_environment (fixture): Configure the environment for the execution of the test.
        restart_syscheckd (fixture): Restarts syscheck.
        wait_for_fim_start (fixture): Waits until the first FIM scan is completed.

    Raises:
        TimeoutError: If an expected event couldn't be captured.
        ValueError: If the path of the event is wrong.
    """

    logger.info('Applying the test configuration')
    check_apply_test(tags_to_apply, get_configuration['tags'])
    logger.info('Checking the event...')
    events = wazuh_log_monitor.start(timeout=20,
                                     callback=fim.callback_audit_added_rule,
                                     accum_results=3,
                                     error_message='Folders were not added to Audit rules list'
                                     ).result()

    assert testdir1 in events, f'{testdir1} not detected in scan'
    assert testdir2 in events, f'{testdir2} not detected in scan'
    assert testdir3 in events, f'{testdir3} not detected in scan'


@pytest.mark.parametrize('tags_to_apply', [
    ({'config1'})
])
def test_readded_rules(tags_to_apply, get_configuration,
                       configure_environment, restart_syscheckd):
    """Check if the removed rules are added to Audit rules list.

    Args:
        tags_to_apply (set): Run test if matches with a configuration identifier, skip otherwise.
        get_configuration (fixture): Gets the current configuration of the test.
        configure_environment (fixture): Configure the environment for the execution of the test.
        restart_syscheckd (fixture): Restarts syscheck.
        wait_for_fim_start (fixture): Waits until the first FIM scan is completed.

    Raises:
        TimeoutError: If an expected event couldn't be captured.
        ValueError: If the path of the event is wrong.
    """

    logger.info('Applying the test configuration')
    check_apply_test(tags_to_apply, get_configuration['tags'])

    # Remove added rules
    for dir_ in (testdir1, testdir2, testdir3):
        command = f"auditctl -W {dir_} -p wa -k wazuh_fim"
        os.system(command)

        wazuh_log_monitor.start(timeout=20,
                                callback=fim.callback_audit_rules_manipulation,
                                error_message=f'Did not receive expected "manipulation" event with the '
                                              f'command {command}')

        events = wazuh_log_monitor.start(timeout=10,
                                         callback=fim.callback_audit_added_rule,
                                         error_message='Did not receive expected "added" event with the rule '
                                                       'modification').result()

        assert dir_ in events, f'{dir_} not in {events}'


@pytest.mark.parametrize('tags_to_apply', [
    ({'config1'})
])
def test_readded_rules_on_restart(tags_to_apply, get_configuration,
                                  configure_environment, restart_syscheckd):
    """Check if the rules are added to Audit when it restarts.

    Args:
        tags_to_apply (set): Run test if matches with a configuration identifier, skip otherwise.
        get_configuration (fixture): Gets the current configuration of the test.
        configure_environment (fixture): Configure the environment for the execution of the test.
        restart_syscheckd (fixture): Restarts syscheck.
        wait_for_fim_start (fixture): Waits until the first FIM scan is completed.

    Raises:
        TimeoutError: If an expected event couldn't be captured.
        ValueError: If the path of the event is wrong.
    """

    logger.info('Applying the test configuration')
    check_apply_test(tags_to_apply, get_configuration['tags'])

    # Restart Audit
    restart_command = ["service", "auditd", "restart"]
    p = subprocess.Popen(restart_command)
    p.wait()

    wazuh_log_monitor.start(timeout=10,
                            callback=fim.callback_audit_connection,
                            error_message=f'Did not receive expected "connect" event with the command '
                                          f'{" ".join(restart_command)}')

    events = wazuh_log_monitor.start(timeout=30,
                                     callback=fim.callback_audit_added_rule,
                                     accum_results=3,
                                     error_message=f'Did not receive expected "load" event with the command '
                                                   f'{" ".join(restart_command)}').result()

    assert testdir1 in events, f'{testdir1} not in {events}'
    assert testdir2 in events, f'{testdir2} not in {events}'
    assert testdir3 in events, f'{testdir3} not in {events}'


@pytest.mark.parametrize('tags_to_apply', [
    ({'config1'})
])
def test_move_rules_realtime(tags_to_apply, get_configuration,
                             configure_environment, restart_syscheckd):
    """Check if the rules are changed to realtime when Audit stops.

    Args:
        tags_to_apply (set): Run test if matches with a configuration identifier, skip otherwise.
        get_configuration (fixture): Gets the current configuration of the test.
        configure_environment (fixture): Configure the environment for the execution of the test.
        restart_syscheckd (fixture): Restarts syscheck.
        wait_for_fim_start (fixture): Waits until the first FIM scan is completed.
    Raises:
        TimeoutError: If an expected event couldn't be captured.
        ValueError: If the path of the event is wrong.
    """

    logger.info('Applying the test configuration')
    check_apply_test(tags_to_apply, get_configuration['tags'])

    # Stop Audit
    stop_command = ["service", "auditd", "stop"]
    p = subprocess.Popen(stop_command)
    p.wait()

    events = wazuh_log_monitor.start(timeout=30,
                                     callback=fim.callback_realtime_added_directory,
                                     accum_results=3,
                                     error_message=f'Did not receive expected "directory added" for monitoring '
                                                   f'with the command {" ".join(stop_command)}').result()

    assert testdir1 in events, f'{testdir1} not detected in scan'
    assert testdir2 in events, f'{testdir2} not detected in scan'
    assert testdir3 in events, f'{testdir3} not detected in scan'

    # Start Audit
    p = subprocess.Popen(["service", "auditd", "start"])
    p.wait()


@pytest.mark.parametrize('audit_key, path', [
    ("custom_audit_key", "/testdir1")
])
def test_audit_key(audit_key, path, get_configuration, configure_environment, restart_syscheckd):
    """Check `<audit_key>` functionality by adding a audit rule and checking if alerts with that key are triggered when
    a file is created.

    Args:
        audit_key (str): Name of the audit_key to monitor.
        tags_to_apply (set): Run test if matches with a configuration identifier, skip otherwise.
        get_configuration (fixture): Gets the current configuration of the test.
        configure_environment (fixture): Configure the environment for the execution of the test.
        restart_syscheckd (fixture): Restarts syscheck.
        wait_for_fim_start (fixture): Waits until the first FIM scan is completed.

    Raises:
        TimeoutError: If an expected event couldn't be captured.
        ValueError: If the path of the event is wrong.
    """

    logger.info('Applying the test configuration')
    check_apply_test({audit_key}, get_configuration['tags'])

    # Add watch rule
    add_rule_command = "auditctl -w " + path + " -p wa -k " + audit_key
    os.system(add_rule_command)

    # Restart and for wazuh
    control_service('stop')
    truncate_file(fim.LOG_FILE_PATH)
    wazuh_log_monitor = FileMonitor(fim.LOG_FILE_PATH)
    control_service('start')
    fim.detect_initial_scan(wazuh_log_monitor)

    # Look for audit_key word
    fim.create_file(fim.REGULAR, path, "testfile")
    events = wazuh_log_monitor.start(timeout=30,
                                     callback=fim.callback_audit_key,
                                     accum_results=1,
                                     error_message=f'Did not receive expected "Match audit_key ..." event '
                                                   f'with the command {" ".join(add_rule_command)}').result()
    assert audit_key in events

    # Remove watch rule
    os.system("auditctl -W " + path + " -p wa -k " + audit_key)


@pytest.mark.parametrize('tags_to_apply, should_restart', [
    ({'audit_key'}, True),
    ({'restart_audit_false'}, False)
])
def test_restart_audit(tags_to_apply, should_restart, get_configuration, configure_environment, restart_syscheckd):
    """Check `<restart_audit>` functionality by removing the plugin and monitoring audit to see if it restart and create
    the file again.

    Args:
        tags_to_apply (set): Run test if matches with a configuration identifier, skip otherwise.
        should_restart (boolean): True if Auditd should restart, False otherwise
        get_configuration (fixture): Gets the current configuration of the test.
        configure_environment (fixture): Configure the environment for the execution of the test.
        restart_syscheckd (fixture): Restarts syscheck.
        wait_for_fim_start (fixture): Waits until the first FIM scan is completed.

    Raises:
        TimeoutError: If an expected event couldn't be captured.
        ValueError: If the time before the and after the restart are equal when auditd has been restarted or if the time
                    before and after the restart are different when auditd hasn't been restarted
    """
    logger.info('Applying the test configuration')
    check_apply_test(tags_to_apply, get_configuration['tags'])

    # We need to retry get_audit_creation_time in case syscheckd didn't have
    # enough time to boot auditd    
    @retry(Exception, attempts=2, delay=3, delay_multiplier=1)
    def get_audit_creation_time():
        for proc in psutil.process_iter(attrs=['name']):
            if proc.name() == "auditd":
                logger.info(f"auditd detected. PID: {proc.pid}")
                return proc.create_time()
        raise Exception('Auditd is not running')

    audisp_path = '/etc/audisp/plugins.d/af_wazuh.conf'
    audit_path = '/etc/audit/plugins.d/af_wazuh.conf'

    if os.path.exists(audisp_path):
        plugin_path = audisp_path
        remove_file(plugin_path)
    elif os.path.exists(audit_path):
        plugin_path = audit_path
        remove_file(plugin_path)
    else:
        raise Exception('The path could not be found because auditd was not running')

    time_before_restart = get_audit_creation_time()
    control_service('restart')
    try:
        check_daemon_status(timeout=global_parameters.default_timeout)
    except TimeoutError:
        pass
    time_after_restart = get_audit_creation_time()

    if should_restart:
        assert time_before_restart != time_after_restart, 'The time before restart audit is equal to ' \
                                                          'the time after restart'
    else:
        assert time_before_restart == time_after_restart, 'The time before restart audit is not equal to ' \
                                                          'the time after restart'

    assert os.path.isfile(plugin_path)
