# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest

from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.fim import LOG_FILE_PATH, generate_params, callback_empty_directories
from wazuh_testing import global_parameters

# Marks

pytestmark = pytest.mark.tier(level=0)


# Variables

test_directories = []
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)


# Configurations

p, m = generate_params(extra_params={'TEST_DIRECTORIES': '', 'MODULE_NAME': __name__})
configuration1 = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)

p, m = generate_params(extra_params={'TEST_DIRECTORIES': '/testdir', 'MODULE_NAME': __name__})
configuration2 = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)

# Merge both list of configurations into the final one to avoid skips and configuration issues
configurations = configuration1 + configuration2


# Fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Tests

@pytest.mark.parametrize('tags_to_apply', [
    {'ossec_conf'}
])
def test_new_directory(tags_to_apply, get_configuration, configure_environment, restart_syscheckd):
    """Verify that syscheck shows a debug message when an empty directories tag is found.

    Parameters
    ----------
    tags_to_apply : set
        Run test if matches with a configuration identifier, skip otherwise
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])

    # Check that the warning is displayed when there is no directory.
    if not get_configuration['elements'][1]['directories']['value']:
        wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                callback=callback_empty_directories,
                                error_message='[ERROR] Did not receive expected '
                                              '"DEBUG: (6338): Empty directories tag found in the configuration" '
                                              'event').result()
    # Check that the message is not displayed when the directory is specified.
    else:
        with pytest.raises(TimeoutError):
            event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                            callback=callback_empty_directories).result()
            raise AttributeError(f'Unexpected event {event}')
