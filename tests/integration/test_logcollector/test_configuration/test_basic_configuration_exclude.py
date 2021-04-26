# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
import pytest
import wazuh_testing.api as api
from wazuh_testing.tools.services import get_service
import wazuh_testing.logcollector as logcollector
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import LOG_COLLECTOR_DETECTOR_PREFIX, AGENT_DETECTOR_PREFIX
from wazuh_testing.tools.services import get_process_cmd, check_if_process_is_running


# Marks
pytestmark = pytest.mark.tier(level=0)

# Configuration
no_restart_windows_after_configuration_set = True
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_basic_configuration.yaml')

wazuh_component = get_service()

if sys.platform == 'win32':
    prefix = AGENT_DETECTOR_PREFIX
else:
    prefix = LOG_COLLECTOR_DETECTOR_PREFIX


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
    """Check if the Wazuh run correctly with the specified exclude field value.

    Ensure logcollector allows the specified exclude attribute. Also, in case of the manager instance, check if the API
    answer for localfile block coincides.

    Raises:
        TimeoutError: In the case of a Windows system, the callback for an invalid location pattern is not generated.
        AssertError: In the case of a server instance, the API response is different that the real configuration.
    """
    cfg = get_configuration['metadata']

    if sys.platform == 'win32':
        log_callback = logcollector.callback_invalid_location_pattern(cfg['location'], prefix=prefix)
        wazuh_log_monitor.start(timeout=5, callback=log_callback,
                                error_message=logcollector.GENERIC_CALLBACK_ERROR_INVALID_LOCATION)

    if wazuh_component == 'wazuh-manager':
        api.wait_until_api_ready()
        api.compare_config_api_response([cfg], 'localfile')

    else:
        if sys.platform == 'win32':
            assert get_process_cmd('wazuh-agent.exe') != 'None'
        else:
            assert check_if_process_is_running('wazuh-logcollector')
