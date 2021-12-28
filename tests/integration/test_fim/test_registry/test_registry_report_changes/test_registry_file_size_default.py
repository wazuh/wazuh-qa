'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts
       when these files are modified. Specifically, these tests will check if FIM limits
       the size of the monitored value to generate 'diff' information to the default limit
       of the 'file_size' tag when the 'report_changes' option is enabled.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured
       files for changes to the checksums, permissions, and ownership.

tier: 1

modules:
    - fim

components:
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
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html#file-size

pytest_args:
    - fim_mode:
        realtime: Enable real-time monitoring on Linux (using the 'inotify' system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the 'who-data' information.
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - fim_registry_report_changes
'''
import os

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, KEY_WOW64_32KEY, KEY_WOW64_64KEY, generate_params, create_registry, registry_parser, modify_registry_value, \
    check_time_travel, validate_registry_value_event, callback_value_event, REG_SZ
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.monitoring import FileMonitor, callback_generator
from wazuh_testing.tools.services import control_service
from wazuh_testing.fim_module.fim_variables import CB_MAXIMUM_FILE_SIZE

# Marks

pytestmark = [pytest.mark.win32, pytest.mark.tier(level=1)]

# Variables

key = "HKEY_LOCAL_MACHINE"
sub_key_1 = "SOFTWARE\\test_key"
sub_key_2 = "SOFTWARE\\Classes\\test_key"

test_regs = [os.path.join(key, sub_key_1),
             os.path.join(key, sub_key_2)]

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
reg1, reg2 = test_regs
DEFAULT_SIZE = 50 * 1024

# Configurations

p, m = generate_params(modes=['scheduled'], extra_params={'WINDOWS_REGISTRY_1': reg1,
                                                          'WINDOWS_REGISTRY_2': reg2})

configurations_path = os.path.join(test_data_path, 'wazuh_registry_report_changes.yaml')

configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# Fixtures

@pytest.fixture(scope='function')
def restart_syscheckd_each_time(request):
    control_service('stop', daemon='wazuh-syscheckd')
    truncate_file(LOG_FILE_PATH)
    file_monitor = FileMonitor(LOG_FILE_PATH)
    setattr(request.module, 'wazuh_log_monitor', file_monitor)
    control_service('start', daemon='wazuh-syscheckd')


@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.mark.parametrize('key, subkey, arch, value_name, tags_to_apply', [
    (key, sub_key_1, KEY_WOW64_64KEY, "some_value", {'test_report_changes'}),
    (key, sub_key_1, KEY_WOW64_32KEY, "some_value", {'test_report_changes'}),
    (key, sub_key_2, KEY_WOW64_64KEY, "some_value", {'test_report_changes'})
])
@pytest.mark.skip(reason="It will be blocked by #1602, when it was solve we can enable again this test")
def test_file_size_default(key, subkey, arch, value_name, tags_to_apply,
                           get_configuration, configure_environment, restart_syscheckd_each_time):
    '''
    description: Check if the 'wazuh-syscheckd' daemon limits the size of the monitored value to generate
                 'diff' information from the default limit of the 'file_size' option. For this purpose,
                 the test will monitor a key and, once the FIM is started, it will wait for the FIM event
                 related to the maximum file size limit to generate 'diff' information and create and
                 modify a testing value. Finally, the test will verify that the value gotten from the
                 FIM event corresponds with the default value of the 'file_size' tag (50MB), and the FIM
                 'added' y 'modified' events from the testing value have been generated properly.

    wazuh_min_version: 4.2.0

    parameters:
        - key:
            type: str
            brief: Path of the registry root key (HKEY_* constants).
        - subkey:
            type: str
            brief: The registry key being monitored by syscheck.
        - arch:
            type: str
            brief: Architecture of the registry.
        - value_name:
            type: str
            brief: Name of the testing value that will be created
        - tags_to_apply:
            type: set
            brief: Run test if matches with a configuration identifier, skip otherwise.
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - restart_syscheckd_each_time:
            type: fixture
            brief: Clear the 'ossec.log' file and start a new monitor on each test case.

    assertions:
        - Verify that an FIM event is generated indicating tthe maximum file size limit
          to generate 'diff' information to the default limit of the 'file_size' tag (50MB).
        - Verify that FIM events are generated when adding and modifying a testing value.

    input_description: A test case (test_report_changes) is contained in external YAML file
                       (wazuh_registry_report_changes.yaml) which includes configuration
                       settings for the 'wazuh-syscheckd' daemon. That is combined with
                       the testing registry keys to be monitored defined in this module.

    expected_output:
        - r'.*Maximum file size limit to generate diff information configured to .*'
        - r'.*Sending FIM event: (.+)$' ('added' and 'modified' events)

    tags:
        - scheduled
        - time_travel
    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])
    mode = get_configuration['metadata']['fim_mode']

    file_size_values = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                               callback=callback_generator(CB_MAXIMUM_FILE_SIZE),
                                               accum_results=3,
                                               error_message='Did not receive expected '
                                                             '"Maximum file size limit to generate diff information '
                                                             'configured to \'... KB\'..." event'
                                               ).result()
    for value in file_size_values:
        if value:
            assert value == str(DEFAULT_SIZE), 'Wrong value for file_size'
        else:
            raise AssertionError('Wrong value for file_size')

    key_h = create_registry(registry_parser[key], subkey, arch)

    modify_registry_value(key_h, "some_value", REG_SZ, "some content")
    check_time_travel(True, monitor=wazuh_log_monitor)
    event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_value_event,
                                    error_message='Did not receive expected '
                                                                    '"Sending FIM event: ..." event').result()
    validate_registry_value_event(event, mode=mode)
