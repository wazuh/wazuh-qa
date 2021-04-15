# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
import wazuh_testing.api as api
import wazuh_testing.logcollector as logcollector
from wazuh_testing.tools.configuration import load_wazuh_configurations
import sys

# Marks
pytestmark = pytest.mark.tier(level=0)



# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_basic_configuration.yaml')

parameters = [
    {'LOG_FORMAT': 'eventchannel', 'QUERY': 'Event[System/EventID = 4624]'},
    {'LOG_FORMAT': 'eventchannel', 'QUERY': 'Event[System/EventID = 1343 and '
                                            '(EventData/Data[@Name=\'LogonType\'] = 2',
     },
    {'LOG_FORMAT': 'eventchannel', 'QUERY': 'Event[System/EventID = 6632 and '
                                            '(EventData/Data[@Name=\'LogonType\'] = 93 or '
                                            'EventData/Data[@Name=\'LogonType\'] = 111)]',
     },
    {'LOG_FORMAT': 'eventchannel', 'QUERY': 'Testing',
     },
    {'LOG_FORMAT': 'eventchannel', 'QUERY': 'Event[System/TESTINGID = 344]',
     },
]
metadata = [
    {'log_format': 'eventchannel', 'query': 'Event[System/EventID = 4624]',
     'valid_value': True
     },
    {'log_format': 'eventchannel', 'query': 'Event[System/EventID = 1343 and '
                                            '(EventData/Data[@Name=\'LogonType\'] = 2',
     'valid_value': True
     },
    {'log_format': 'eventchannel', 'query': 'Event[System/EventID = 6632 and '
                                            '(EventData/Data[@Name=\'LogonType\'] = 93 or '
                                            'EventData/Data[@Name=\'LogonType\'] = 111)]',
     'valid_value': True
     },
    {'log_format': 'eventchannel', 'query': 'Testing', 'valid_value': False},
    {'log_format': 'eventchannel', 'query': 'Event[System/TESTINGID = 344]',
     'valid_value': False
     },
]

configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=parameters,
                                           metadata=metadata)
configuration_ids = [f"{x['LOG_FORMAT'], x['QUERY']}" for x in parameters]


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.mark.skipif(sys.platform != 'win32',
                    reason="Windows is required for this test")
def test_configuration_query_valid(get_configuration, configure_environment, restart_logcollector):
    """
    """
    cfg = get_configuration['metadata']
    if not cfg['valid_value']:
        pytest.skip('Invalid values provided')

    real_configuration = cfg.copy()
    real_configuration.pop('valid_value')
    api.compare_config_api_response([real_configuration], 'localfile')


@pytest.mark.skipif(sys.platform != 'win32',
                    reason="Windows is required for this test")
def test_configuration_query_invalid(get_configuration, configure_environment, restart_logcollector):
    """
    """
    cfg = get_configuration['metadata']
    if cfg['valid_value']:
        pytest.skip('Invalid values provided')

    log_callback = logcollector.callback_query_bad_format('SECURITY')
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message="The expected error output has not been produced")
