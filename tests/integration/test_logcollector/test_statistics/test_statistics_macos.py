# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import sys
from json import load
import tempfile

import pytest
import wazuh_testing.tools.configuration as conf
from wazuh_testing import logcollector
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools import LOGCOLLECTOR_STATISTICS_FILE
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.services import control_service

from time import sleep

# Marks
pytestmark = [pytest.mark.darwin, pytest.mark.tier(level=1)]

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data', 'configuration')
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

# Fixtures
@pytest.fixture(scope="module")
def get_local_internal_options():
    """Get configurations from the module."""
    return local_internal_options


@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_options_state_interval_no_file(get_local_internal_options, get_configuration, 
                                        configure_environment, restart_logcollector):
    """Check if the monitorized file does appear in logcollector.state.

    Raises:
        AssertionError: If the elapsed time is different from the interval.
        TimeoutError: If the expected callback is not generated.
    """

    # Ensure wazuh-logcollector.state is created
    logcollector.wait_statistics_file(timeout=10)

    with open(LOGCOLLECTOR_STATISTICS_FILE, 'r') as json_file:
        data = load(json_file)

    global_files = data['global']['files']
    interval_files = data['interval']['files']

    assert list(filter(lambda global_file: global_file['location'] == 'macos', global_files))
    assert list(filter(lambda interval_file: interval_file['location'] == 'macos', interval_files))
