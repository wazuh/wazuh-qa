# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
import pytest
import wazuh_testing.api as api
from wazuh_testing.tools import get_service
from wazuh_testing.tools.services import get_service
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import LOG_COLLECTOR_DETECTOR_PREFIX, AGENT_DETECTOR_PREFIX


# Marks
pytestmark = pytest.mark.tier(level=0)

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_basic_configuration.yaml')

wazuh_component = get_service()

if wazuh_component == 'wazuh-manager':
    prefix = LOG_COLLECTOR_DETECTOR_PREFIX
else:
    prefix = AGENT_DETECTOR_PREFIX


if sys.platform == 'win32':
    parameters = [
        {'LOG_FORMAT': 'syslog', 'LOCATION': r'C:\tmp\*', 'EXCLUDE': r'C:\tmp\file.txt'},
        {'LOG_FORMAT': 'syslog', 'LOCATION': r'C:\tmp\*', 'EXCLUDE': r'C:\tmp\*.txt'},
        {'LOG_FORMAT': 'syslog', 'LOCATION': r'C:\tmp\*', 'EXCLUDE': r'C:\tmp\file.*'},
        {'LOG_FORMAT': 'syslog', 'LOCATION': r'C:\tmp\*', 'EXCLUDE': r'C:\tmp\file.*'},
        {'LOG_FORMAT': 'syslog', 'LOCATION': r'C:\tmp\*', 'EXCLUDE': r'C:\tmp\file.log-%Y-%m-%d'},
    ]

    metadata = [
        {'log_format': 'syslog', 'location': r'C:\tmp\*', 'exclude': r'C:\tmp\file.txt'},
        {'log_format': 'syslog', 'location': r'C:\tmp\*', 'exclude': r'C:\tmp\*.txt'},
        {'log_format': 'syslog', 'location': r'C:\tmp\*', 'exclude': r'C:\tmp\file.*'},
        {'log_format': 'syslog', 'location': r'C:\tmp\*', 'exclude': r'C:\tmp\file.*'},
        {'log_format': 'syslog', 'location': r'C:\tmp\*', 'exclude': r'C:\tmp\file.log-%Y-%m-%d'},
    ]

else:
    parameters = [
        {'LOG_FORMAT': 'syslog', 'LOCATION': '/tmp/testing/*', 'EXCLUDE': '/tmp/testing/file.txt'},
        {'LOG_FORMAT': 'syslog', 'LOCATION': '/tmp/testing/*', 'EXCLUDE': '/tmp/testing/f*'},
        {'LOG_FORMAT': 'syslog', 'LOCATION': '/tmp/testing/*', 'EXCLUDE': '/tmp/testing/*g'},
        {'LOG_FORMAT': 'syslog', 'LOCATION': '/tmp/testing/*', 'EXCLUDE': '/tmp/testing/file?.txt'},
        {'LOG_FORMAT': 'syslog', 'LOCATION': '/tmp/testing/*', 'EXCLUDE': '/tmp/testing/file.log-%Y-%m-%d'},
    ]

    metadata = [
        {'log_format': 'syslog', 'location': '/tmp/testing/*', 'exclude': '/tmp/testing/file.txt'},
        {'log_format': 'syslog', 'location': '/tmp/testing/*', 'exclude': '/tmp/testing/f*'},
        {'log_format': 'syslog', 'location': '/tmp/testing/*', 'exclude': '/tmp/testing/*g'},
        {'log_format': 'syslog', 'location': '/tmp/testing/*', 'exclude': '/tmp/testing/file?.txt'},
        {'log_format': 'syslog', 'location': '/tmp/testing/*', 'exclude': '/tmp/testing/file.log-%Y-%m-%d'},
    ]

configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=parameters,
                                           metadata=metadata)
configuration_ids = [f"{x['LOG_FORMAT'], x['LOCATION'], x['EXCLUDE']}" for x in parameters]


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_configuration_exclude(get_configuration, configure_environment, restart_logcollector):
    """
    """
    cfg = get_configuration['metadata']

    if wazuh_component == 'wazuh-manager':
        api.wait_until_api_ready()
        api.compare_config_api_response([cfg], 'localfile')

