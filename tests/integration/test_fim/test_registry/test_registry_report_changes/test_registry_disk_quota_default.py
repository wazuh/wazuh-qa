# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, KEY_WOW64_32KEY, KEY_WOW64_64KEY, generate_params, \
                              callback_disk_quota_default, create_registry, registry_parser, modify_registry_value, \
                              check_time_travel, validate_registry_value_event, callback_detect_event, REG_SZ
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.services import control_service
from wazuh_testing.tools.file import truncate_file


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
DEFAULT_SIZE = 1024 * 1024


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
def test_disk_quota_default(key, subkey, arch, value_name, tags_to_apply,
                            get_configuration, configure_environment, restart_syscheckd_each_time):
    """
    Check that no events are sent when the disk_quota exceeded

    Parameters
    ----------
    key : str
        Root key (HKEY_*)
    subkey : str
        path of the registry.
    arch : str
        Architecture of the registry.
    value_name : str
        Name of the value that will be created
    tags_to_apply : set
        Run test if match with a configuration identifier, skip otherwise.
    size : int
        Size of the content to write in value
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])
    mode = get_configuration['metadata']['fim_mode']

    disk_quota_value = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                               callback=callback_disk_quota_default,
                                               error_message='Did not receive expected '
                                               '"Maximum disk quota size limit configured to \'... KB\'." event'
                                               ).result()
    if disk_quota_value:
        assert disk_quota_value == str(DEFAULT_SIZE), 'Wrong value for disk_quota'
    else:
        raise AssertionError('Wrong value for disk_quota')

    key_h = create_registry(registry_parser[key], subkey, arch)

    modify_registry_value(key_h, "some_value", REG_SZ, "some content")
    check_time_travel(True, monitor=wazuh_log_monitor)
    events = wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_event,
                                     accum_results=2, error_message='Did not receive expected '
                                     '"Sending FIM event: ..." event').result()
    for ev in events:
        validate_registry_value_event(ev, mode=mode)
