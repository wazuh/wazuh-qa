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
    {'SOCKET_NAME': 'custom_socket', 'SOCKET_PATH': '/var/log/messages', 'LOCATION': "/tmp/testing.log",
     'LOG_FORMAT': 'syslog', 'TARGET': 'custom_socket', 'OUT_FORMAT': '$(timestamp %Y-%m-%d %H:%M:%S)',
     'TARGET_OUT_FORMAT': 'custom_socket'},
    {'SOCKET_NAME': 'custom_socket', 'SOCKET_PATH': '/var/log/messages', 'LOCATION': "/tmp/testing.log",
     'LOG_FORMAT': 'syslog', 'TARGET': 'custom_socket', 'OUT_FORMAT': '$(log)',
     'TARGET_OUT_FORMAT': 'custom_socket'},
    {'SOCKET_NAME': 'custom_socket', 'SOCKET_PATH': '/var/log/messages', 'LOCATION': "/tmp/testing.log",
     'LOG_FORMAT': 'syslog', 'TARGET': 'custom_socket', 'OUT_FORMAT': '$(base64_log)',
     'TARGET_OUT_FORMAT': 'custom_socket'},
    {'SOCKET_NAME': 'custom_socket', 'SOCKET_PATH': '/var/log/messages', 'LOCATION': "/tmp/testing.log",
     'LOG_FORMAT': 'syslog', 'TARGET': 'custom_socket', 'OUT_FORMAT': '$(json_escaped_log)',
     'TARGET_OUT_FORMAT': 'custom_socket'},
    {'SOCKET_NAME': 'custom_socket', 'SOCKET_PATH': '/var/log/messages', 'LOCATION': "/tmp/testing.log",
     'LOG_FORMAT': 'syslog', 'TARGET': 'custom_socket', 'OUT_FORMAT': '$(location)',
     'TARGET_OUT_FORMAT': 'custom_socket'},
    {'SOCKET_NAME': 'custom_socket', 'SOCKET_PATH': '/var/log/messages', 'LOCATION': "/tmp/testing.log",
     'LOG_FORMAT': 'syslog', 'TARGET': 'custom_socket', 'OUT_FORMAT': '$(output)',
     'TARGET_OUT_FORMAT': 'custom_socket'},
    {'SOCKET_NAME': 'custom_socket', 'SOCKET_PATH': '/var/log/messages', 'LOCATION': "/tmp/testing.log",
     'LOG_FORMAT': 'syslog', 'TARGET': 'custom_socket', 'OUT_FORMAT': '$(command)',
     'TARGET_OUT_FORMAT': 'custom_socket'},
    {'SOCKET_NAME': 'custom_socket', 'SOCKET_PATH': '/var/log/messages', 'LOCATION': "/tmp/testing.log",
     'LOG_FORMAT': 'syslog', 'TARGET': 'custom_socket', 'OUT_FORMAT': '$(timestamp)',
     'TARGET_OUT_FORMAT': 'custom_socket'},
    {'SOCKET_NAME': 'custom_socket', 'SOCKET_PATH': '/var/log/messages', 'LOCATION': "/tmp/testing.log",
     'LOG_FORMAT': 'syslog', 'TARGET': 'custom_socket', 'OUT_FORMAT': '$(hostname)',
     'TARGET_OUT_FORMAT': 'custom_socket'},
    {'SOCKET_NAME': 'custom_socket', 'SOCKET_PATH': '/var/log/messages', 'LOCATION': "/tmp/testing.log",
     'LOG_FORMAT': 'syslog', 'TARGET': 'custom_socket', 'OUT_FORMAT': '$(host_ip)',
     'TARGET_OUT_FORMAT': 'custom_socket'},
    {'SOCKET_NAME': 'custom_socket', 'SOCKET_PATH': '/var/log/messages', 'LOCATION': "/tmp/testing.log",
     'LOG_FORMAT': 'syslog', 'TARGET': 'custom_socket', 'OUT_FORMAT': '$(host_ip)',
     'TARGET_OUT_FORMAT': 'no_defined_custom_socket'},
]
metadata = [
    {'socket_name': 'custom_socket', 'socket_path': '/var/log/messages', 'location': "/tmp/testing.log",
     'log_format': 'syslog', 'target': 'custom_socket', 'out_format': '$(timestamp %Y-%m-%d %H:%M:%S)',
     'target_out_format': 'custom_socket', 'valid_value': True},
    {'socket_name': 'custom_socket', 'socket_path': '/var/log/messages', 'location': "/tmp/testing.log",
     'log_format': 'syslog', 'target': 'custom_socket', 'out_format': '$(log)',
     'target_out_format': 'custom_socket', 'valid_value': True},
    {'socket_name': 'custom_socket', 'socket_path': '/var/log/messages', 'location': "/tmp/testing.log",
     'log_format': 'syslog', 'target': 'custom_socket', 'out_format': '$(base64_log)',
     'target_out_format': 'custom_socket', 'valid_value': True},
    {'socket_name': 'custom_socket', 'socket_path': '/var/log/messages', 'location': "/tmp/testing.log",
     'log_format': 'syslog', 'target': 'custom_socket', 'out_format': '$(json_escaped_log)',
     'target_out_format': 'custom_socket', 'valid_value': True},
    {'socket_name': 'custom_socket', 'socket_path': '/var/log/messages', 'location': "/tmp/testing.log",
     'log_format': 'syslog', 'target': 'custom_socket', 'out_format': '$(location)',
     'target_out_format': 'custom_socket', 'valid_value': True},
    {'socket_name': 'custom_socket', 'socket_path': '/var/log/messages', 'location': "/tmp/testing.log",
     'log_format': 'syslog', 'target': 'custom_socket', 'out_format': '$(output)',
     'target_out_format': 'custom_socket', 'valid_value': True},
    {'socket_name': 'custom_socket', 'socket_path': '/var/log/messages', 'location': "/tmp/testing.log",
     'log_format': 'syslog', 'target': 'custom_socket', 'out_format': '$(command)',
     'target_out_format': 'custom_socket', 'valid_value': True},
    {'socket_name': 'custom_socket', 'socket_path': '/var/log/messages', 'location': "/tmp/testing.log",
     'log_format': 'syslog', 'target': 'custom_socket', 'out_format': '$(timestamp)',
     'target_out_format': 'custom_socket', 'valid_value': True},
    {'socket_name': 'custom_socket', 'socket_path': '/var/log/messages', 'location': "/tmp/testing.log",
     'log_format': 'syslog', 'target': 'custom_socket', 'out_format': '$(hostname)',
     'target_out_format': 'custom_socket', 'valid_value': True},
    {'socket_name': 'custom_socket', 'socket_path': '/var/log/messages', 'location': "/tmp/testing.log",
     'log_format': 'syslog', 'target': 'custom_socket', 'out_format': '$(host_ip)',
     'target_out_format': 'custom_socket', 'valid_value': True},
    {'socket_name': 'custom_socket', 'socket_path': '/var/log/messages', 'location': "/tmp/testing.log",
     'log_format': 'syslog', 'target': 'custom_socket', 'out_format': '$(host_ip)',
     'target_out_format': 'no_defined_custom_socket', 'valid_value': False},
]

configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=parameters,
                                           metadata=metadata)
configuration_ids = \
    [f"{x['LOG_FORMAT'], x['TARGET'], x['SOCKET_NAME'], x['LOCATION'], x['SOCKET_PATH'], x['TARGET_OUT_FORMAT'], x['OUT_FORMAT']}" for x in parameters]


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_configuration_out_format_valid(get_configuration, configure_environment, restart_logcollector):
    """
    """
    cfg = get_configuration['metadata']
    if not cfg['valid_value']:
        pytest.skip('Invalid values provided')


    log_callback = logcollector.callback_socket_target(cfg['location'], cfg['target'])
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                                error_message="The expected error output has not been produced")

    real_configuration = dict((key, cfg[key]) for key in ('location', 'target', 'log_format'))
    real_configuration['out_format'] = {'target': cfg['target_out_format'], 'item': cfg['out_format']}
    api.compare_config_api_response([real_configuration], 'localfile')


@pytest.mark.skipif(sys.platform == 'win32',
                    reason="Windows system currently does not support this test required")
def test_configuration_out_format_invalid(get_configuration, configure_environment, restart_logcollector):
    """
    """
    cfg = get_configuration['metadata']
    if cfg['valid_value']:
        pytest.skip('Invalid values provided')

    log_callback = logcollector.callback_log_target_not_found(cfg['location'], cfg['target_out_format'])
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                                error_message="The expected error output has not been produced")
