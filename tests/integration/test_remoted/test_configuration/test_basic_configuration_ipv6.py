# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
import time
import wazuh_testing.api as api
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
    {'CONNECTION': 'secure'},
    {'CONNECTION': 'syslog'}
]

metadata = [
    {'connection': 'secure'},
    {'connection': 'syslog'}
]

configurations = load_wazuh_configurations(configurations_path, __name__ , params=parameters, metadata=metadata)
configuration_ids = [f"{x['CONNECTION']}" for x in parameters]


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_ipv6(get_configuration, configure_environment):
    """
    """
    truncate_file(LOG_FILE_PATH)
    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

    control_service('restart', daemon='wazuh-remoted')
    time.sleep(1)
    cfg = get_configuration['metadata']
    if cfg['connection'] == 'secure':
        log_callback = make_callback(
            fr"WARNING: \(\d+\): Secure connection does not support IPv6. IPv4 will be used instead.",
            REMOTED_DETECTOR_PREFIX
        )
        wazuh_log_monitor.start(timeout=5, callback=log_callback, error_message="The expected warning output has not been produced.")

    # Check that API query return the selected configuration
    for field in cfg.keys():
        api_answer = api.get_manager_configuration(section="remote", field=field)
        if field == 'protocol':
            array_protocol = np.array(cfg[field].split(","))
            assert (array_protocol == api_answer).all(), "Wazuh API answer different from introduced configuration"
        else:
            assert cfg[field] == api_answer, "Wazuh API answer different from introduced configuration"

