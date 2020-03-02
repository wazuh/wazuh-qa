# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest

from wazuh_testing import global_parameters
from wazuh_testing.fim import (LOG_FILE_PATH, generate_params, regular_file_cud, callback_detect_end_scan)
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = pytest.mark.tier(level=0)

# variables

test_directories = [os.path.join(PREFIX, 'testdir')]

directory_str = test_directories[0]

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf_disabled.yaml')
testdir = test_directories[0]

# configurations

conf_params = {'TEST_DIRECTORIES': directory_str}
p, m = generate_params(extra_params=conf_params)

configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests

def test_disabled(get_configuration, configure_environment, restart_syscheckd):
    """Check if syscheckd sends events when disabled="yes".

    Parameters
    ----------
    folder : str
        Path where files will be created.
    """
    # Expect a timeout when checking for syscheckd initial scan
    with pytest.raises(TimeoutError):
        event = wazuh_log_monitor.start(timeout=10, callback=callback_detect_end_scan)
        raise AttributeError(f'Unexpected event {event}')

    # Use `regular_file_cud` and don't expect any event
    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'
    if scheduled:
        with pytest.raises(TimeoutError):
            wazuh_log_monitor.start(timeout=10, callback=callback_detect_end_scan)
    else:
        regular_file_cud(testdir, wazuh_log_monitor, time_travel=scheduled, min_timeout=global_parameters.default_timeout,
                         triggers_event=False)
