'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check if the 'wazuh-syscheckd' and 'auditd' daemons work together properly.
       The 'who-data' feature of the of the File Integrity Monitoring (FIM) system uses the Linux Audit
       subsystem to get the information about who made the changes in a monitored directory.
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

@pytest.mark.xfail(reason="It will be blocked by #2174, when it was solve we can enable again this test")
@pytest.mark.parametrize('tags_to_apply', [
    ({'config1'})
])
def test_audit_health_check(tags_to_apply, get_configuration,
                            configure_environment, restart_syscheckd):
    '''
    description: Check if the health check of the 'auditd' daemon is passed.
                 For this purpose, the test will monitor a testing folder using
                 'who-data' and it will check that the health check passed
                 verifying that the proper FIM event is generated.

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
        - Verify that the 'who-data' health check of FIM is passed.

    input_description: A test case (config1) is contained in external YAML file (wazuh_conf.yaml)
                       which includes configuration settings for the 'wazuh-syscheckd' daemon
                       and, it is combined with the testing directories to be monitored
                       defined in this module.

    expected_output:
        - r'Whodata health-check: Success.'

    tags:
        - who-data
    '''
    logger.info('Applying the test configuration')
    check_apply_test(tags_to_apply, get_configuration['tags'])

    wazuh_log_monitor.start(timeout=20, callback=fim.callback_audit_health_check,
                            error_message='Health check failed')


@pytest.mark.xfail(reason="It will be blocked by #2174, when it was solve we can enable again this test")
@pytest.mark.parametrize('tags_to_apply', [
    ({'config1'})
])
def test_added_rules(tags_to_apply, get_configuration,
                     configure_environment, restart_syscheckd):
    '''
    description: Check if the specified folders are added to the 'audit' rules list.
                 For this purpose, the test will monitor several folders using 'who-data'.
                 Once FIM starts, the test will check if the a rule for every monitored
                 directory is added verifying that the proper FIM event is generated.

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
        - Verify that FIM adds 'audit' rules for the monitored directories.

    input_description: A test case (config1) is contained in external YAML file (wazuh_conf.yaml)
                       which includes configuration settings for the 'wazuh-syscheckd' daemon
                       and, it is combined with the testing directories to be monitored
                       defined in this module.

    expected_output:
        - r'.*Added audit rule for monitoring directory'

    tags:
        - audit-rules
        - who-data
    '''
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


@pytest.mark.xfail(reason="It will be blocked by #2174, when it was solve we can enable again this test")
@pytest.mark.parametrize('tags_to_apply', [
    ({'config1'})
])
def test_readded_rules(tags_to_apply, get_configuration,
                       configure_environment, restart_syscheckd):
    '''
    description: Check if the removed rules are added to the audit rules list.
                 For this purpose, the test will monitor several folders using 'who-data'.
                 Once FIM starts, the test will remove the audit rule (using 'auditctl')
                 and will wait until the manipulation event is triggered. Finally, the test
                 will check that the 'audit' rule is added again verifying that
                 the proper FIM event is generated.

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
        - Verify that FIM is able to re-add 'audit' rules for the monitored directories.

    input_description: A test case (config1) is contained in external YAML file (wazuh_conf.yaml)
                       which includes configuration settings for the 'wazuh-syscheckd' daemon
                       and, it is combined with the testing directories to be monitored
                       defined in this module.

    expected_output:
        - r'.*Added audit rule for monitoring directory'

    tags:
        - audit-rules
        - who-data
    '''
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

@pytest.mark.xfail(reason="It will be blocked by #2174, when it was solve we can enable again this test")
@pytest.mark.parametrize('tags_to_apply', [
    ({'config1'})
])
def test_readded_rules_on_restart(tags_to_apply, get_configuration,
                                  configure_environment, restart_syscheckd):
    '''
    description: Check if FIM is able to add the 'audit' rules when the 'auditd' daemon is restarted.
                 For this purpose, the test will monitor a folder using 'whodata'. Once FIM starts,
                 the test will restart the 'auditd' daemon and, it will wait until it has started.
                 After 'auditd' is running, the test will wait for the FIM 'connect' and
                 'load rule' events to be generated.

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
        - Verify that FIM adds the 'audit' rules for the monitored directories
          after the 'auditd' daemon restarting.

    input_description: A test case (config1) is contained in external YAML file (wazuh_conf.yaml)
                       which includes configuration settings for the 'wazuh-syscheckd' daemon
                       and, it is combined with the testing directories to be monitored
                       defined in this module.

    expected_output:
        - r'Audit: connected'
        - r'.*Added audit rule for monitoring directory'

    tags:
        - audit-rules
        - who-data
    '''
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

@pytest.mark.xfail(reason="It will be blocked by #2174, when it was solve we can enable again this test")
@pytest.mark.parametrize('tags_to_apply', [
    ({'config1'})
])
def test_move_rules_realtime(tags_to_apply, get_configuration,
                             configure_environment, restart_syscheckd):
    '''
    description: Check if FIM switches the monitoring mode of the testing directories from 'who-data'
                 to 'realtime' when the 'auditd' daemon stops. For this purpose, the test will monitor
                 several folders using 'whodata'. Once FIM starts, the test will stop the auditd service.
                 Then it will wait until the monitored directories using 'whodata' are monitored with
                 'realtime', verifying that the proper FIM events are generated.

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
        - Verify that FIM switches the monitoring mode of the testing directories from 'whodata' to 'realtime'

    input_description: A test case (config1) is contained in external YAML file (wazuh_conf.yaml)
                       which includes configuration settings for the 'wazuh-syscheckd' daemon
                       and, it is combined with the testing directories to be monitored
                       defined in this module.

    expected_output:
        - r'.*Directory added for real time monitoring'

    tags:
        - realtime
        - who-data
    '''
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


@pytest.mark.xfail(reason="It will be blocked by #2174, when it was solve we can enable again this test")
@pytest.mark.parametrize('audit_key, path', [
    ("custom_audit_key", "/testdir1")
])
def test_audit_key(audit_key, path, get_configuration, configure_environment, restart_syscheckd):
    '''
    description: Check the 'audit_key' functionality by adding a 'audit' rule and checking if alerts with
                 that key are triggered when a file is created. The 'audit' keys are keywords that allow
                 identifying which audit rules generate particular events. For this purpose, the test
                 will manually add a rule for a monitored path using a custom 'audit' key. After FIM starts,
                 the test will check that the events that are generated with the custom key are processed.

    wazuh_min_version: 4.2.0

    parameters:
        - audit_key:
            type: str
            brief: Name of the 'audit_key' to monitor.
        - path:
            type: str
            brief: Path to the audit_key
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
        - Verify that the 'Match audit_key' event of FIM is generated correctly.

    input_description: A test case (audit_key) is contained in external YAML file (wazuh_conf.yaml)
                       which includes configuration settings for the 'wazuh-syscheckd' daemon
                       and, it is combined with the testing directories to be monitored
                       defined in this module.

    expected_output:
        - r'Match audit_key' ('key="wazuh_hc"' and 'key="wazuh_fim"' must not appear in the event)

    tags:
        - audit-keys
        - who-data
    '''
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

@pytest.mark.xfail(reason="It will be blocked by #2174, when it was solve we can enable again this test")
@pytest.mark.parametrize('tags_to_apply, should_restart', [
    ({'audit_key'}, True),
    ({'restart_audit_false'}, False)
])
def test_restart_audit(tags_to_apply, should_restart, get_configuration, configure_environment, restart_syscheckd):
    '''
    description: Check the 'restart_audit' functionality by removing the 'af_wazuh.conf' plugin used
                 by the 'auditd' daemon and monitoring the 'auditd' process to see if it restart and
                 and finally, it checks if the deleted plugin is created again.

    wazuh_min_version: 4.2.0

    parameters:
        - tags_to_apply:
            type: set
            brief: Run test if match with a configuration identifier, skip otherwise.
        - should_restart:
            type: bool
            brief: True if the 'auditd' daemon should restart, False otherwise.
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
        - Verify that the 'auditd' process is created again when restarting
          this service by checking its creation time.
        - Verify that the 'auditd' process is not killed when the restart command
          is not sent by checking its creation time.
        - Verify that the 'af_wazuh.conf' plugin of the 'auditd' daemon
          is created again after being deleted.

    input_description: Two test cases (audit_key and restart_audit_false) are contained in external
                       YAML file (wazuh_conf.yaml) which includes configuration settings for
                       the 'wazuh-syscheckd' daemon.

    expected_output:
        - The creation time of the 'auditd' daemon process.

    tags:
        - audit-keys
        - who-data
    '''
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
