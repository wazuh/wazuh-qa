# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import pytest

from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools import LOGCOLLECTOR_STATISTICS_FILE
from wazuh_testing.tools.file import read_json
from wazuh_testing import logcollector

# Marks
pytestmark = [pytest.mark.darwin, pytest.mark.tier(level=1)]

# Configuration
logcollector_stats_file_tout = 30
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_statistics_macos.yaml')

parameters = [
    {'LOCATION': 'macos', 'LOG_FORMAT': 'macos'},
]

metadata = [
    {'location': 'macos', 'log_format': 'macos'}
]

# Configuration data
configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)
configuration_ids = [f"{x['LOCATION']}_{x['LOG_FORMAT']}" for x in parameters]

local_internal_options = {'logcollector.state_interval': 1}

daemons_handler_configuration = {'daemons': ['wazuh-logcollector', 'wazuh-agentd', 'wazuh-execd'], 'ignore_errors': False}


@pytest.fixture(scope='module', params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_options_state_interval_no_file(configure_local_internal_options_module,
                                        get_configuration,
                                        configure_environment,
                                        daemons_handler):
    """Check if the monitored file appears in logcollector.state.

    Raises:
        AssertionError: If the elapsed time is different from the interval.
        TimeoutError: If the expected callback is not generated in the expected time.
    """

    # Ensure wazuh-logcollector.state is created
    logcollector.wait_statistics_file(timeout=logcollector_stats_file_tout)

    data = read_json(LOGCOLLECTOR_STATISTICS_FILE)

    global_files = data['global']['files']
    interval_files = data['interval']['files']

    assert list(filter(lambda global_file: global_file['location'] == 'macos', global_files))
    assert list(filter(lambda interval_file: interval_file['location'] == 'macos', interval_files))
