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
import wazuh_testing.api as api


# Marks
pytestmark = pytest.mark.tier(level=0)

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_basic_configuration.yaml')


# Setting parameters for testing queue_size too big
parameters = [
    {'CONNECTION': 'secure', 'PORT': '1514', 'QUEUE_SIZE': '99999999'}
]

metadata = [
    {'connection': 'secure', 'port': '1514', 'queue_size': '99999999'}
]

configurations = load_wazuh_configurations(configurations_path, "test_basic_configuration_queue_size" , params=parameters,
                                           metadata=metadata)

configuration_ids = [f"{x['CONNECTION'],x['PORT'], x['QUEUE_SIZE']}" for x in parameters]


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_big_queue_size(get_configuration, configure_environment):
    truncate_file(LOG_FILE_PATH)
    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

    cfg = get_configuration['metadata']

    control_service('restart', daemon='wazuh-remoted')
    log_callback = make_callback(
        fr"WARNING: Queue size is very high. The application may run out of memory.",
        REMOTED_DETECTOR_PREFIX
    )
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message="The expected warning output has not been produced.")

    for field in cfg.keys():
        api_answer = api.get_manager_configuration(section="remote", field=field)
        assert cfg[field] == api_answer , "Wazuh API answer different from introduced configuration"