# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
import time
import numpy as np
from wazuh_testing.tools import LOG_FILE_PATH

from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.monitoring import make_callback, REMOTED_DETECTOR_PREFIX
from wazuh_testing.tools.services import control_service
import wazuh_testing.api as api


# Marks
pytestmark = pytest.mark.tier(level=0)

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_basic_configuration.yaml')

parameters = [
    {'PROTOCOL': 'TCP', 'CONNECTION': 'Testing', 'PORT': '1514'}
]
metadata = [
    {'protocol': 'TCP', 'connection': 'Testing', 'port': '1514'}
]

configurations = load_wazuh_configurations(configurations_path, "test_basic_configuration_connection", params=parameters, metadata=metadata)
configuration_ids = [f"{x['PROTOCOL']}_{x['CONNECTION']}_{x['PORT']}" for x in parameters]


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_invalid_connection(get_configuration, configure_environment):
    """

    """
    truncate_file(LOG_FILE_PATH)
    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
    cfg = get_configuration['metadata']
    try:
        control_service('restart', daemon='wazuh-remoted')

    except:

        log_callback = make_callback(
            fr"ERROR: \(\d+\): Invalid value for element 'connection': {cfg['connection']}.",
            REMOTED_DETECTOR_PREFIX
        )
        wazuh_log_monitor.start(timeout=5, callback=log_callback,
                                error_message="Wazuh remoted didn't start as expected.")

        log_callback = make_callback(
            fr"ERROR: \(\d+\): Configuration error at '/var/ossec/etc/ossec.conf'.",
            REMOTED_DETECTOR_PREFIX
        )
        wazuh_log_monitor.start(timeout=5, callback=log_callback,
                                error_message="Wazuh remoted didn't start as expected.")

        log_callback = make_callback(
            fr"CRITICAL: \(\d+\): Configuration error at '/var/ossec/etc/ossec.conf'.",
            REMOTED_DETECTOR_PREFIX
        )
        wazuh_log_monitor.start(timeout=5, callback=log_callback,
                                error_message="Wazuh remoted didn't start as expected.")