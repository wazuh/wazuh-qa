# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest

from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.monitoring import make_callback, REMOTED_DETECTOR_PREFIX
from wazuh_testing.tools.services import control_service

# Marks
pytestmark = pytest.mark.tier(level=0)

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_basic_configuration.yaml')

parameters = [
    {'CONNECTION': 'secure', 'PORT': '1514', 'RIDS_CLOSING_TIME': '0s'},
    {'CONNECTION': 'secure', 'PORT': '1514', 'RIDS_CLOSING_TIME': '4S'}
]

metadata = [
    {'connection': 'secure', 'port': '1514', 'rids_closing_time': '0'},
    {'connection': 'secure', 'port': '1514', 'rids_closing_time': '4S'}
]

configurations = load_wazuh_configurations(configurations_path, "test_basic_configuration_rids_closing_time" , params=parameters,
                                           metadata=metadata)
configuration_ids = [f"{x['CONNECTION'],x['PORT'],x['RIDS_CLOSING_TIME']}" for x in parameters]


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_rids_closing_time_invalid(get_configuration, configure_environment):
    truncate_file(LOG_FILE_PATH)
    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

    try:
        control_service('restart', daemon='wazuh-remoted')
        assert 0
    except:

        log_callback = make_callback(
            fr"ERROR: Invalid value for option '\<rids_closing_time\>'",
            REMOTED_DETECTOR_PREFIX
        )
        wazuh_log_monitor.start(timeout=5, callback=log_callback,
                                error_message="The expected error output has not been produced.")
