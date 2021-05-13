# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
import wazuh_testing.logcollector as logcollector
from wazuh_testing.tools.configuration import load_wazuh_configurations
import sys
from wazuh_testing.tools.utils import lower_case_key_dictionary_array

# Marks
common_query = ['', 'Testing', '!ras*^']
query_list = []

if sys.platform != 'win32' and sys.platform != 'darwin':
    pytestmark = [pytest.mark.skip, pytest.mark.tier(level=0)]
else:
    if sys.platform == 'darwin':
        clauses = ['eventMessage', 'processImagePath', 'senderImagePath', 'subsystem', 'category', 'eventType',
                   'messageType']
        location = 'oslog'
        log_format = 'oslog'
        for clause in clauses:
            query_list.append([f'{clause} CONTAINS[c] "com.apple.geod"',
                               f'{clause} == "testing"',
                               f'{clause} <> "testing"',
                               f'{clause} = "testing"',
                               f'{clause} <= "testing"',
                               f'{clause} >= "testing"',
                               f'{clause} = > "testing"',
                               f'{clause} < "testing"',
                               f'{clause} < "testing"',
                               f'{clause} < "testing"',
                               f'{clause} <= "testing" AND  {clause} == "testing"',
                               f'{clause} <= "testing" & &  {clause} == "testing"',
                               f'{clause} <= "testing" OR  {clause} == "testing"',
                               f'{clause} <= "testing" | |  {clause} == "testing"',
                               f'NOT {clause} <= "testing"',
                               f'! {clause} <= "testing"',
                               f'! {clause} BEGINSWITH[c] "testing"',
                               f'! {clause} ENDSWITH[c] "testing"',
                               f'! {clause} LIKE[c] "testing"',
                               f'! {clause} MATCHES[c] "testing"',
                               f'! {clause} BEGINSWITH[c] "testing"',
                               f'! {clause} BEGINSWITH[c] "testing"',
                               f'! {clause} IN "testing"',
                               ])
    else:
        location = logcollector.WINDOWS_CHANNEL_LIST
        log_format = 'eventchannel'
        query_list = ['Event[System/EventID = 4624]',
                      'Event[System/EventID = 1343 and (EventData/Data[@Name=\'LogonType\'] = 2',
                      'Event[System/EventID = 6632 and (EventData/Data[@Name=\'LogonType\'] = 93 or '
                      'EventData/Data[@Name=\'LogonType\'] = 111)]',
                      'Event[EventData[Data[@Name="property"]="value"]]',
                      'Event[EventData[Data="value"]]',
                      'Event[ EventData[Data[@Name="PropA"]="ValueA" and  Data[@Name="PropB"]="ValueB" ]]'
                      ]


query_list += common_query
pytestmark = pytest.mark.tier(level=0)

# Configuration
no_restart_windows_after_configuration_set = True
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_basic_configuration.yaml')

parameters = []
for query in query_list:
    if isinstance(location, list):
        for channel in location:
            parameters.append({'LOCATION': f'{location}', 'LOG_FORMAT': f'{log_format}', 'QUERY': f'{query}'})
    else:
        parameters.append({'LOCATION': f'{location}', 'LOG_FORMAT': f'{log_format}', 'QUERY': f'{query}'})

metadata = lower_case_key_dictionary_array(parameters)

configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=parameters,
                                           metadata=metadata)
configuration_ids = [f"{x['LOCATION'], x['LOG_FORMAT'], x['QUERY']}" for x in parameters]


@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_configuration_query_valid(get_configuration, configure_environment, restart_logcollector):
    """Check if the Wazuh run correctly with the specified query attributes.

    Ensure logcollector allows the specified query attribute.

    Raises:
        TimeoutError: If the callback for analyzing eventchannel is not generated
    """

    configuration = get_configuration['metadata']
    log_format = configuration['log_format']

    if log_format == 'oslog':
        log_callback = logcollector.callback_macos_oslog_monitoring()
        wazuh_log_monitor.start(timeout=5, callback=log_callback,
                                error_message=logcollector.GENERIC_CALLBACK_ERROR_ANALYZING_EVENTCHANNEL)
    else:
        log_callback = logcollector.callback_eventchannel_analyzing('Security')
        wazuh_log_monitor.start(timeout=5, callback=log_callback,
                                error_message=logcollector.GENERIC_CALLBACK_ERROR_ANALYZING_EVENTCHANNEL)
