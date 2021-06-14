# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os

import pytest
from wazuh_testing import logcollector
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.remote import check_agent_received_message
import inspect
from time import sleep

# Marks
pytestmark = [pytest.mark.darwin, pytest.mark.tier(level=1)]

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')

configurations_path_query = os.path.join(test_data_path, 'wazuh_macos_format_query.yaml')
configurations_path_query_type = os.path.join(test_data_path, 'wazuh_macos_format_query_type.yaml')
configurations_path_query_level = os.path.join(test_data_path, 'wazuh_macos_format_query_level.yaml')
configurations_path_query_type_level = os.path.join(test_data_path, 'wazuh_macos_format_query_type_level.yaml')

parameters = []
metadata = []

parameters_query_type_level = []
metadata_query_type_level = []

parameters_query_level = []
metadata_query_level = []

parameters_query_type = []
metadata_query_type = []

parameters_query = []
metadata_query = []


def contains_lambda_function(string, false=False):
    if false:
        return lambda clause: not string in clause
    else:
        return lambda clause: string in clause


def begin_with_lambda_function(string, false=False):
    if false:
        return lambda clause: not clause.startswith(string)
    else:
        return lambda clause: clause.startswith(string)


def end_with_lambda_function(string, false=False):
    if false:
        return lambda clause: not clause.endswith(string)
    else:
        return lambda clause: clause.endswith(string)


def equal_lambda_function(string, false=False):
    if false:
        return lambda clause: clause != string
    else:
        return lambda clause: clause == string


def combine_lambda_function(lambda_function_1, lambda_function_2, lambda_function_1_string, lambda_function2_string,
                            logical_operation):
    if logical_operation == 'AND':
        return lambda clause: lambda_function_1(lambda_function_1_string) and lambda_function_2(lambda_function2_string)
    elif logical_operation == 'OR':
        return lambda clause: lambda_function_1(lambda_function_1_string) or lambda_function_2(lambda_function2_string)


macos_log_list = [
    {
        'program_name': 'logger',
        'message': "Logger testing message.",
    },
    {
        'program_name': 'logger',
        'message': "Not match Logger testing message.",
    },
    {
        'program_name': 'logger',
        'message': "Logger testing message not match.",
    },
    {
        'program_name': 'logger',
        'message': "Logger testingtestingnegative",
    },
    {
        'program_name': 'customlog',
        'level': 'default',
        'type': 'log',
        'subsystem': 'testing.wazuhagent.macos',
        'category': 'category'
    },
    {
        'program_name': 'customlogactivity',
        'level': 'default',
        'type': 'activity',
        'subsystem': '',
        'category': ''
    },
    {
        'program_name': 'customlogtrace',
        'level': 'default',
        'type': 'trace',
        'subsystem': '',
        'category': ''
    },
    {
        'program_name': 'customlog',
        'level': 'error',
        'type': 'log',
        'subsystem': 'testing.wazuhagent.macos',
        'category': 'category'
    },
    {
        'program_name': 'customlog1',
        'level': 'error',
        'type': 'log',
        'subsystem': 'testing.wazuhagent.macos',
        'category': 'category'
    },

    {
        'program_name': 'customloginfo',
        'level': 'info',
        'type': 'log',
        'subsystem': 'testing.wazuhagent.macos',
        'category': 'category'
    },
    {
        'program_name': 'customlogdebug',
        'level': 'debug',
        'type': 'log',
        'subsystem': 'testing.wazuhagent.macos',
        'category': 'category'
    }
]

query_list = [
    {
        'query_predicate': 'eventMessage == "Logger testing message."',
        'level': 'default',
        'type': 'log',
        'lambda_function': equal_lambda_function("Logger testing message."),
        'clause': ['message']
    },
    {
        'query_predicate': 'process = "logger"',
        'level': 'default',
        'type': 'log',
        'lambda_function': equal_lambda_function("logger"),
        'clause': ['program_name']
    },
    {
        'query_predicate': 'eventMessage CONTAINS[c] "Logger testing" AND eventMessage CONTAINS[c] "testingnegative"',
        'level': 'default',
        'type': 'log',
        'lambda_function': lambda message: "Logger testing" in message and "testingnegative" in message,
        'clause': ['message']
    },

    {
        'query_predicate': 'NOT messageType == "default"',
        'level': 'default',
        'type': 'log',
        'lambda_function': equal_lambda_function("default", True),
        'clause': ['level'],
    },

    {
        'query_predicate': 'messageType == "error"',
        'level': 'default',
        'type': 'log',
        'lambda_function': equal_lambda_function("error"),
        'clause': ['level'],
        'real_type': 'error'
    },

    {
        'query_predicate': 'messageType == "fault"',
        'level': 'default',
        'type': 'log',
        'lambda_function': equal_lambda_function("fault"),
        'clause': ['level'],
        'real_type': 'fault'
    },

    {
        'query_predicate': 'eventType == "logEvent"',
        'level': 'default',
        'type': 'log',
        'lambda_function': equal_lambda_function("log"),
        'clause': ['type']
    },

    {
        'query_predicate': 'eventType == "traceEvent"',
        'level': 'default',
        'type': 'log',
        'lambda_function': equal_lambda_function("trace"),
        'clause': ['type'],
        'real_type': 'trace'
    },

    {
        'query_predicate': 'eventType == "activityCreateEvent"',
        'level': 'default',
        'type': 'log',
        'lambda_function': equal_lambda_function("activity"),
        'clause': ['type'],
        'real_type': 'activity'
    },

    {
        'query_predicate': 'process == "customlog"',
        'level': 'info',
        'type': 'log',
        'lambda_function': equal_lambda_function("customlog"),
        'clause': ['program_name']
    },

    {
        'query_predicate': 'process == "customlog"',
        'level': 'debug',
        'type': 'log',
        'lambda_function': equal_lambda_function("customlog"),
        'clause': ['program_name']
    },

    {
        'query_predicate': 'process == "customlog"',
        'level': 'default',
        'type': 'activity',
        'lambda_function': equal_lambda_function("customlog"),
        'clause': ['program_name']
    },

    {
        'query_predicate': 'process == "customlog"',
        'level': 'default',
        'type': 'trace',
        'lambda_function': equal_lambda_function("customlog"),
        'clause': ['program_name']
    },

    {
        'query_predicate': 'category CONTAINS[c] "examplecategory1"',
        'level': 'default',
        'type': 'log',
        'lambda_function': contains_lambda_function("examplecategory1"),
        'clause': ['category']
    },

    {
        'query_predicate': 'subsystem BEGINSWITH[c] "com"',
        'level': 'default',
        'type': 'log',
        'lambda_function': begin_with_lambda_function("com"),
        'clause': ['subsystem']
    },

    {
        'query_predicate': '! subsystem ENDSWITH[c] "com"',
        'level': 'default',
        'type': 'log',
        'lambda_function': end_with_lambda_function("com", True),
        'clause': ['subsystem']
    },

    {
        'query_predicate': 'process == "logger" AND eventMessage CONTAINS[c] "Custom oslog event message"',
        'level': 'default',
        'type': 'log',
        'lambda_function': lambda process, eventMessage: process == 'logger'
                                                         and "Custom oslog event message" in eventMessage,
        'clause': ['program_name', 'message']
    },

    {
        'query_predicate': 'process BEGINSWITH[c] "custom" OR subsystem ENDSWITH[c] "example"',
        'level': 'default',
        'type': 'activity',
        'lambda_function': lambda process, subsystem: process.startswith("custom") or subsystem.endswith("example"),
        'clause': ['program_name', 'subsystem']
    },
]

for query in query_list:
    parameters_query_type_level += [{'QUERY': query['query_predicate'], 'TYPE': query['type'], 'LEVEL': query['level']}]
    metadata_query_type_level += [{'query': query['query_predicate'], 'type': query['type'], 'level': query['level'],
                                   'lambda_function': query['lambda_function'], 'clause': query['clause']}]

    parameters_query_level += [{'QUERY': query['query_predicate'], 'LEVEL': query['level']}]
    metadata_query_level += [{'query': query['query_predicate'], 'level': query['level'],
                              'lambda_function': query['lambda_function'], 'clause': query['clause']}]

    parameters_query_type += [{'QUERY': query['query_predicate'], 'TYPE': query['type']}]
    metadata_query_type += [{'query': query['query_predicate'], 'type': query['type'],
                             'lambda_function': query['lambda_function'], 'clause': query['clause']}]

    parameters_query += [{'QUERY': query['query_predicate']}]
    metadata_query += [{'query': query['query_predicate'], 'lambda_function': query['lambda_function'],
                        'clause': query['clause']}]

configurations = load_wazuh_configurations(configurations_path_query_type_level, __name__,
                                           params=parameters_query_type_level, metadata=metadata_query_type_level)
configurations += load_wazuh_configurations(configurations_path_query_type, __name__,
                                            params=parameters_query_type, metadata=metadata_query_type)
configurations += load_wazuh_configurations(configurations_path_query_level, __name__,
                                            params=parameters_query_level, metadata=metadata_query_level)
configurations += load_wazuh_configurations(configurations_path_query, __name__,
                                            params=parameters_query, metadata=metadata_query)

configuration_ids = [f"{x['query']}_{x['level']}_{x['type']}" for x in metadata_query_type_level] + \
                    [f"{x['query']}_{x['level']}" for x in metadata_query_level] + \
                    [f"{x['query']}_{x['type']}" for x in metadata_query_type] + \
                    [f"{x['query']}" for x in metadata_query]


# Fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.fixture(scope="module")
def get_connection_configuration():
    """Get configurations from the module."""
    return logcollector.DEFAULT_AUTHD_REMOTED_SIMULATOR_CONFIGURATION


def test_macos_format_only_future_events(get_configuration, configure_environment, get_connection_configuration,
                                         init_authd_remote_simulator, restart_logcollector):
    """Check if logcollector use correctly query option using macos log format.

    Raises:
        TimeoutError: If the expected callback is not generated.
    """

    sleep(10)

    cfg = get_configuration['metadata']

    macos_logcollector_monitored = logcollector.callback_monitoring_macos_logs
    wazuh_log_monitor.start(timeout=30, callback=macos_logcollector_monitored,
                            error_message=logcollector.GENERIC_CALLBACK_ERROR_ANALYZING_MACOS)

    ## Generate macOS log messages

    for macos_log in macos_log_list:
        log_message_command = macos_log['program_name']

        if log_message_command == 'logger':
            logcollector.generate_macos_logger_log(macos_log['message'])

        else:
            logcollector.generate_macos_custom_log(macos_log['type'], macos_log['level'], macos_log['subsystem'],
                                                   macos_log['category'], macos_log['program_name'])

        log_message_command = macos_log['program_name']
        clauses_values = []

        same_type = True
        same_level = True

        macos_log_type = macos_log['type'] if 'type' in macos_log else 'log'
        macos_log_level = macos_log['level'] if 'level' in macos_log else 'default'

        if macos_log['program_name'] != 'logger':
            if macos_log['type'] == 'activity':
                macos_log['message'] = logcollector.TEMPLATE_ACTIVITY_MESSAGE
            elif macos_log['type'] == 'log':
                macos_log['message'] = logcollector.TEMPLATE_OSLOG_MESSAGE
            elif macos_log['type'] == 'trace':
                macos_log['message'] = logcollector.TEMPLATE_TRACE_MESSAGE

        macos_log['type'] = macos_log_type
        macos_log['level'] = macos_log_level

        configuration_level = cfg['level'] if 'level' in cfg else 'default'
        configuration_type = cfg['type'] if 'type' in cfg else 'log'

        if 'type' in cfg:
            if macos_log_type != configuration_type:
                same_type = False

        if logcollector.MAP_MACOS_LEVEL_VALUE[macos_log_level] < logcollector.MAP_MACOS_LEVEL_VALUE[
            configuration_level]:
            same_level = False

        for clause in cfg['clause']:
            clause_value = str(macos_log[clause]) if clause in macos_log else ""
            clauses_values += [clause_value]

        if log_message_command == 'logger':
            expected_macos_message = logcollector.format_macos_message_pattern(macos_log['program_name'],
                                                                               macos_log['message'])
        else:
            expected_macos_message = logcollector.format_macos_message_pattern(
                macos_log['program_name'],
                macos_log['message'], type=macos_log['type'], subsystem=macos_log['subsystem'],
                category=macos_log['category'])

        if cfg['lambda_function'](*clauses_values) and same_level and same_type:
            check_agent_received_message(remoted_simulator.rcv_msg_queue, expected_macos_message, timeout=60)
        else:
            with pytest.raises(TimeoutError):
                check_agent_received_message(remoted_simulator.rcv_msg_queue, expected_macos_message, timeout=5)
