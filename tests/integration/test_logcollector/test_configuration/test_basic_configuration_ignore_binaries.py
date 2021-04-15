# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
import sys

from wazuh_testing.tools.configuration import load_wazuh_configurations
import wazuh_testing.generic_callbacks as gc
from wazuh_testing.tools import get_service

import wazuh_testing.api as api
from wazuh_testing.tools.monitoring import LOG_COLLECTOR_DETECTOR_PREFIX, AGENT_DETECTOR_PREFIX


# Marks
pytestmark = pytest.mark.tier(level=0)

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_basic_configuration.yaml')

if sys.platform == 'win32':
    location = r'C:\testing\files*'
    wazuh_configuration = 'ossec.conf'

else:
    location = '/tmp/testing/files*'
    wazuh_configuration = 'etc/ossec.conf'


wazuh_component = get_service()

if wazuh_component == 'wazuh-manager':
    prefix = LOG_COLLECTOR_DETECTOR_PREFIX
else:
    prefix = AGENT_DETECTOR_PREFIX


parameters = [
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'syslog', 'IGNORE_BINARIES': 'yes'},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'syslog', 'IGNORE_BINARIES': 'no'},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'syslog', 'IGNORE_BINARIES': 'yesTesting'},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'syslog', 'IGNORE_BINARIES': 'noTesting'},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'syslog', 'IGNORE_BINARIES': 'testingvalue'},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'syslog', 'IGNORE_BINARIES': '1234'}

]

metadata = [
    {'location': f'{location}', 'log_format': 'syslog', 'ignore_binaries': 'yes', 'valid_value': True},
    {'location': f'{location}', 'log_format': 'syslog', 'ignore_binaries': 'no', 'valid_value': True},
    {'location': f'{location}', 'log_format': 'syslog', 'ignore_binaries': 'yesTesting', 'valid_value': False},
    {'location': f'{location}', 'log_format': 'syslog', 'ignore_binaries': 'noTesting', 'valid_value': False},
    {'location': f'{location}', 'log_format': 'syslog', 'ignore_binaries': 'testingvalue', 'valid_value': False},
    {'location': f'{location}', 'log_format': 'syslog', 'ignore_binaries': '1234', 'valid_value': False}

]


configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=parameters,
                                           metadata=metadata)
configuration_ids = [f"{x['LOCATION'], x['LOG_FORMAT'], x['IGNORE_BINARIES']}" for x in parameters]


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def check_ignore_binaries_valid(cfg):
    """
    """
    real_configuration = cfg.copy()
    real_configuration.pop('valid_value')
    if wazuh_component == 'wazuh-manager':
        api.wait_until_api_ready()
        api.compare_config_api_response([real_configuration], 'localfile')


def check_ignore_binaries_invalid(cfg):
    """
    """
    log_callback = gc.callback_invalid_value('ignore_binaries', cfg['ignore_binaries'], prefix)
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message="The expected error output has not been produced")

    log_callback = gc.callback_error_in_configuration('ERROR', prefix,
                                                      conf_path=f'{wazuh_configuration}')
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message="The expected error output has not been produced")

    if sys.platform != 'win32':
        log_callback = gc.callback_error_in_configuration('CRITICAL', prefix,
                                                          conf_path=f'{wazuh_configuration}')
        wazuh_log_monitor.start(timeout=5, callback=log_callback,
                                error_message="The expected error output has not been produced")


def test_ignore_binaries(get_configuration, configure_environment, restart_logcollector):
    """
    """
    cfg = get_configuration['metadata']
    if cfg['valid_value']:
        check_ignore_binaries_valid(cfg)
    else:
        check_ignore_binaries_invalid(cfg)
