# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os

import pytest

from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, callback_detect_integrity_event, generate_params
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.win32, pytest.mark.tier(level=1)]

# variables
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
key = "HKEY_LOCAL_MACHINE"
subkey = "SOFTWARE\\test"

configurations_path = os.path.join(test_data_path, 'wazuh_disabled_sync_conf_win32.yaml')

test_directories = [os.path.join(PREFIX, 'testdir1')]
test_regs = [os.path.join(key, subkey)]

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

conf_params = {'TEST_DIRECTORIES': test_directories[0],
               'TEST_REGISTRIES': test_regs[0]}

# configurations

p, m = generate_params(extra_params=conf_params, modes=['scheduled', 'realtime', 'whodata'])

configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)

# fixtures


@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param

# Tests


@pytest.mark.parametrize('tags_to_apply, file_sync, registry_sync, ', [
                        ({'sync_disabled'}, False, False),
                        ({'sync_registry_disabled'}, True, False),
                        ({'sync_registry_enabled'}, True, True)
])
def test_sync_disabled(tags_to_apply, file_sync, registry_sync,
                       get_configuration, configure_environment, restart_syscheckd, wait_for_fim_start_sync_disabled):
    """
    Verify that synchronization is disabled when enabled is set to no in the configuration.
    The expected events are
        DEBUG: (6317): Sending integrity control message: {"component":"fim_file", ........}
        DEBUG: (6317): Sending integrity control message: {"component":"fim_registry",.....}

    Parameters
    ----------
    tags_to_apply: set
        Configuration that will be used in the test.
    file_sync: boolean
        True if file synchronization is enabled
    registry_sync: boolean
        True if registry synchronization is enabled
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])
    if not file_sync:
        # The file synchronization event shouldn't be triggered
        with pytest.raises(TimeoutError):
            event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                            callback=callback_detect_integrity_event, update_position=True).result()
    else:
        # The file synchronization event should be triggered
        event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                        callback=callback_detect_integrity_event, update_position=True).result()
        assert event['component'] == 'fim_file', 'Wrong event component'

    if not registry_sync:
        # The registry synchronization event shouldn't be triggered
        with pytest.raises(TimeoutError):
            event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout, update_position=True,
                                            callback=callback_detect_integrity_event).result()
    else:
        # The registry synchronization event should be triggered
        event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout, update_position=True,
                                        callback=callback_detect_integrity_event).result()
        assert event['component'] == 'fim_registry', 'Wrong event component'
