'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when these
       files are modified. Specifically, these tests will verify that FIM checks at the specified frequency
       in the 'windows_audit_interval' tag, that the SACLs of the directories monitored using the 'whodata'
       monitoring mode are correct, detecting the changes and restoring the SACL rules when required.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured files
       for changes to the checksums, permissions, and ownership.

components:
    - fim

suite: files_windows_audit_interval

targets:
    - agent

daemons:
    - wazuh-syscheckd

os_platform:
    - windows

os_version:
    - Windows 10
    - Windows 8
    - Windows 7
    - Windows Server 2019
    - Windows Server 2016
    - Windows Server 2012
    - Windows Server 2003
    - Windows XP

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html#whodata
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html#windows-audit-interval
    - https://en.wikipedia.org/wiki/Access-control_list

pytest_args:
    - fim_mode:
        realtime: Enable real-time monitoring on Linux (using the 'inotify' system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the 'who-data' information.
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - fim_windows_audit_interval
'''
import os
import platform
import re
import sys

import pytest
from wazuh_testing.fim import LOG_FILE_PATH, generate_params
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.services import control_service

if sys.platform == 'win32':
    from test_fim.test_files.test_windows_audit_interval.manage_acl import Privilege, get_file_security_descriptor, \
        modify_sacl, \
        get_sacl

skiptest_win10 = True if platform.system()=='Windows' and platform.release()=='10' else False
# Marks

pytestmark = [pytest.mark.win32, pytest.mark.tier(level=1)]

# variables

test_directories = [os.path.join(PREFIX, 'testdir_modify_sacl'), os.path.join(PREFIX, 'testdir_restore_sacl')]

directory_str = ','.join(test_directories)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
testdir_modify, testdir_restore = test_directories
WAZUH_RULES = {'DELETE', 'WRITE_DAC', 'FILE_WRITE_DATA', 'FILE_WRITE_ATTRIBUTES'}
previous_rules = set()

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

# configurations

windows_audit_interval = 20
conf_params, conf_metadata = generate_params(extra_params={'TEST_DIRECTORIES': directory_str,
                                                           'WINDOWS_AUDIT_INTERVAL': str(windows_audit_interval)},
                                             modes=['whodata'])

configurations = load_wazuh_configurations(configurations_path, __name__, params=conf_params, metadata=conf_metadata)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# functions
def extra_configuration_before_yield():
    """Get list of SACL before Wazuh applies its own rules based on whodata monitoring."""
    with Privilege('SeSecurityPrivilege'):
        lfss = get_file_security_descriptor(testdir_restore)
        sacl = get_sacl(lfss) if get_sacl(lfss) is not None else set()
        setattr(sys.modules[__name__], 'previous_rules', sacl)


def callback_sacl_changed(line):
    match = re.match(r".*The SACL of \'(.+)\' has been modified and it is not valid for the real-time Whodata mode. "
                     r"Whodata will not be available for this file.", line)
    if match:
        return match.group(1)


def callback_sacl_restored(line):
    match = re.match(r".*The SACL of \'(.+)\' has been restored correctly.", line)
    if match:
        return match.group(1)


# tests
@pytest.mark.skipif(skiptest_win10, reason='refactor required to obtain ACLs on windows 10')
@pytest.mark.parametrize('tags_to_apply', [
    {'audit_interval'}
])
def test_windows_audit_modify_sacl(tags_to_apply, get_configuration, configure_environment, restart_syscheckd,
                                   wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon detects a SACL change every 'windows_audit_interval'
                 and sets monitoring to 'realtime' mode if so. For this purpose, the test will monitor a
                 folder and verify that the SACL rules are applied to it. Then, the test will remove one rule,
                 and finally, it will verify that an FIM event is generated indicating the rule modification
                 and change the monitoring mode to 'realtime'.

    wazuh_min_version: 4.2.0

    tier: 1

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
            brief: Clear the `ossec.log` file and start a new monitor.
        - wait_for_fim_start:
            type: fixture
            brief: Wait for realtime start, whodata start, or end of initial FIM scan.

    assertions:
        - Verify that an FIM event is generated when a SACL modification is detected.

    input_description: A test case (audit_interval) is contained in external YAML file (wazuh_conf.yaml)
                       which includes configuration settings for the 'wazuh-syscheckd' daemon and, it
                       is combined with the testing directory to be monitored defined in this module.
                       For managing the SACL rules, a module 'manage_acl.py' is used.

    expected_output:
        - r'.*The SACL of .* has been modified and it is not valid for the real-time Whodata mode. ' \
           'Whodata will not be available for this file.'

    tags:
        - realtime
        - who_data
    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])

    with Privilege('SeSecurityPrivilege'):
        # Assert that Wazuh rules are added
        lfss = get_file_security_descriptor(testdir_modify)
        dir_rules = get_sacl(lfss)
        assert dir_rules is not None, 'No SACL rules were applied to the monitored directory.'
        for rule in WAZUH_RULES:
            assert rule in dir_rules, f'{rule} not found in {dir_rules}'

        # Delete one of them and assert that after the 'windows_audit_interval' thread, Wazuh is set to real-time
        # monitoring
        modify_sacl(lfss, 'delete', mask=next(iter(WAZUH_RULES)))
        dir_rules = get_sacl(lfss)
        assert next(iter(WAZUH_RULES)) not in dir_rules, f'{next(iter(WAZUH_RULES))} found in {dir_rules}'

    event = wazuh_log_monitor.start(timeout=windows_audit_interval, callback=callback_sacl_changed,
                                    error_message='Did not receive expected "The SACL '
                                                  'of \'...\' has been restored correctly" event').result()
    assert testdir_modify in event, f'{testdir_modify} not detected in SACL modification event'

@pytest.mark.skipif(skiptest_win10, reason='refactor required to obtain ACLs on windows 10')
@pytest.mark.parametrize('tags_to_apply', [
    {'audit_interval'}
])
def test_windows_audit_restore_sacl(tags_to_apply, get_configuration, configure_environment, restart_syscheckd,
                                    wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon restores previous SACL rules when the Wazuh service is stopped.
                 For this purpose, the test will monitor a folder and verify that the Wazuh SACL rules are applied
                 to it. Then, the test will stop the agent service, and finally, it will verify that an FIM event
                 is generated, indicating the restoration of the previous SACL rules.

    wazuh_min_version: 4.2.0

    tier: 1

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
            brief: Clear the `ossec.log` file and start a new monitor.
        - wait_for_fim_start:
            type: fixture
            brief: Wait for realtime start, whodata start, or end of initial FIM scan.

    assertions:
        - Verify that an FIM event is generated indicating that previous SACL rules are restored
          when the Wazuh agent is stopped.

    input_description: A test case (audit_interval) is contained in external YAML file (wazuh_conf.yaml)
                       which includes configuration settings for the 'wazuh-syscheckd' daemon and, it
                       is combined with the testing directory to be monitored defined in this module.
                       For managing the SACL rules, a module 'manage_acl.py' is used.

    expected_output:
        - r'.*The SACL of .* has been restored correctly.'

    tags:
        - realtime
        - who_data
    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])

    with Privilege('SeSecurityPrivilege'):
        lfss = get_file_security_descriptor(testdir_restore)
        dir_rules = set(get_sacl(lfss))
        assert dir_rules - previous_rules == WAZUH_RULES

        # Stop Wazuh service to force SACL rules to be restored
        control_service('stop')
        event = wazuh_log_monitor.start(timeout=5, callback=callback_sacl_restored,
                                        error_message='Did not receive expected "The SACL '
                                                      'of \'...\' has been restored correctly" event').result()
        assert testdir_restore in event, f'{testdir_restore} not detected in SACL restore event'
        dir_rules = set(get_sacl(lfss))
        assert dir_rules == previous_rules, f'{dir_rules} is not equal to {previous_rules}'

    # Start Wazuh service again so the fixture does not crash
    control_service('start')
