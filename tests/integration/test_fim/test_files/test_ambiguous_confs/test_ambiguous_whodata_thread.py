# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, generate_params, callback_real_time_whodata_started
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks


pytestmark = [pytest.mark.linux, pytest.mark.tier(level=2)]

# Variables
test_directories = [os.path.join(PREFIX, 'testdir1')]

directory_str = ','.join(test_directories)
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf_whodata_thread.yaml')
testdir1 = test_directories[0]

# Configurations


p, m = generate_params(extra_params={"TEST_DIRECTORIES": testdir1}, modes=['whodata'])

configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# Fixtures


@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Tests


@pytest.mark.parametrize('whodata_enabled, tags_to_apply', [
    (False, {'whodata_disabled_conf'}),
    (True, {'whodata_enabled_conf'})
])
def test_ambiguous_whodata_thread(whodata_enabled, tags_to_apply, get_configuration, configure_environment,
                                  restart_syscheckd):
    """
    Check if the whodata thread is started when the configuration is ambiguous.

    Configure directory to be monitored both with and without whodata. Depending on the order, the whodata thread should
    or shouldn't start.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])

    if whodata_enabled:
        wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_real_time_whodata_started,
                                error_message='Did not receive expected '
                                              '"File integrity monitoring real-time Whodata engine started" event')
    else:
        with pytest.raises(TimeoutError):
            wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                    callback=callback_real_time_whodata_started)
            raise AttributeError(f'Unexpected event "File integrity monitoring real-time Whodata engine started"')
