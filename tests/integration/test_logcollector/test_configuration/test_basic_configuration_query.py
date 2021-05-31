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
query_list = ['']
parameters = []

level_list = ['default', 'info', 'debug']
type_list = ['log', 'trace', 'activity']
wazuh_configuration = 'wazuh_basic_configuration_query_macos.yaml'

if sys.platform != 'win32' and sys.platform != 'darwin':
    pytestmark = [pytest.mark.skip, pytest.mark.tier(level=0)]
else:
    pytestmark = [pytest.mark.tier(level=0)]
    if sys.platform == 'darwin':
        clauses = ['eventMessage', 'processImagePath', 'senderImagePath', 'subsystem', 'category']
        location = log_format = 'macos'
        for clause in clauses:
            query_list += [f'{clause} CONTAINS[c] "com.apple.geod"',
                           f'{clause} == "testing"',
                           f'{clause} <> "testing"',
                           f'{clause} = "testing"',
                           f'{clause} CONTAINS[c] "testing" AND  {clause} CONTAINS[c] "example"',
                           f'{clause} CONTAINS[c] "testing" &&  {clause} CONTAINS[c] "example"',
                           f'{clause} CONTAINS[c] "testing" OR  {clause} CONTAINS[c] "example"',
                           f'{clause} CONTAINS[c] "testing" ||  {clause} CONTAINS[c] "example"',
                           f'NOT {clause} BEGINSWITH[c] "testing"',
                           f'! {clause} BEGINSWITH[c] "testing"',
                           f'! {clause} ENDSWITH[c] "testing"',
                           f'! {clause} LIKE[c] "testing"',
                           f'! {clause} MATCHES[c] "testing"',
                           f'! {clause} BEGINSWITH[c] "testing"',
                           f'! {clause} IN "testing"',
                           ]
    else:
        wazuh_configuration = 'wazuh_basic_configuration_query_windows.yaml'
        location = ['Security', 'System', 'Application']
        log_format = 'eventchannel'
        query_list += ['Event[System/EventID = 4624]',
                       'Event[System/EventID = 1343 and (EventData/Data[@Name=\'LogonType\'] = 2',
                       'Event[System/EventID = 6632 and (EventData/Data[@Name=\'LogonType\'] = 93 or '
                       'EventData/Data[@Name=\'LogonType\'] = 111)]',
                       'Event[EventData[Data[@Name="property"]="value"]]',
                       'Event[EventData[Data="value"]]',
                       'Event[ EventData[Data[@Name="PropA"]="ValueA" and  Data[@Name="PropB"]="ValueB" ]]'
                       ]

    for query in query_list:
        if isinstance(location, list):
            for channel in location:
                parameters += [{'LOCATION': channel, 'LOG_FORMAT': log_format, 'QUERY': query}]
        else:
            for level in level_list:
                for type in type_list:
                    parameters += [{'LOCATION': location, 'LOG_FORMAT': log_format,
                                       'QUERY': query, 'TYPE': type, 'LEVEL': level}]

metadata = lower_case_key_dictionary_array(parameters)

# Configuration
no_restart_windows_after_configuration_set = True
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, wazuh_configuration)
configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=parameters,
                                           metadata=metadata)

configuration_ids = [f"{x['location']}_{x['log_format']}_{x['query']}_{x['level']}_{x['type']}" + f"" if 'level' in x
                     else f"{x['location']}_{x['log_format']}_{x['query']}" for x in metadata]


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

    if log_format == 'macos':
        log_callback = logcollector.callback_monitoring_macos_logs()
        wazuh_log_monitor.start(timeout=5, callback=log_callback,
                                error_message=logcollector.GENERIC_CALLBACK_ERROR_ANALYZING_EVENTCHANNEL)
    else:
        log_callback = logcollector.callback_eventchannel_analyzing(configuration['location'])
        wazuh_log_monitor.start(timeout=5, callback=log_callback,
                                error_message=logcollector.GENERIC_CALLBACK_ERROR_ANALYZING_EVENTCHANNEL)
