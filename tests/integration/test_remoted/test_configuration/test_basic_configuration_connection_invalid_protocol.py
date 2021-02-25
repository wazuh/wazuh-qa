# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
import time
import numpy as np
from wazuh_testing.tools import LOG_FILE_PATH

from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
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

parameters = [
    {'PROTOCOL': 'Testing,UDP', 'CONNECTION': 'secure', 'PORT': '1514'},
    {'PROTOCOL': 'TCP,Testing', 'CONNECTION': 'secure', 'PORT': '1514'},
    {'PROTOCOL': 'Testing,Testing', 'CONNECTION': 'secure', 'PORT': '1514'},
    {'PROTOCOL': 'TCP,UDP,Testing', 'CONNECTION': 'secure', 'PORT': '1514'},
    {'PROTOCOL': 'Testing,UDP', 'CONNECTION': 'syslog', 'PORT': '514'},
    {'PROTOCOL': 'TCP,Testing', 'CONNECTION': 'syslog', 'PORT': '514'},
    {'PROTOCOL': 'Testing,Testing', 'CONNECTION': 'syslog', 'PORT': '514'},
    {'PROTOCOL': 'TCP,UDP,Testing', 'CONNECTION': 'syslog', 'PORT': '514'}
]
metadata = [
    {'protocol': 'Testing,UDP', 'connection': 'secure', 'port': '1514'},
    {'protocol': 'TCP,Testing', 'connection': 'secure', 'port': '1514'},
    {'protocol': 'Testing,Testing', 'connection': 'secure', 'port': '1514'},
    {'protocol': 'TCP,UDP,Testing', 'connection': 'secure', 'port': '1514'},
    {'protocol': 'Testing,UDP', 'connection': 'syslog', 'port': '514'},
    {'protocol': 'TCP,Testing', 'connection': 'syslog', 'port': '514'},
    {'protocol': 'Testing,Testing', 'connection': 'syslog', 'port': '514'},
    {'protocol': 'TCP,UDP,Testing', 'connection': 'syslog', 'port': '514'}
]

configurations = load_wazuh_configurations(configurations_path, "test_basic_configuration_connection", params=parameters, metadata=metadata)
configuration_ids = [f"{x['PROTOCOL']}_{x['CONNECTION']}_{x['PORT']}" for x in parameters]


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_invalid_protocol(get_configuration, configure_environment):
    """
    """

    truncate_file(LOG_FILE_PATH)
    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

    control_service('restart', daemon='wazuh-remoted')

    cfg = get_configuration['metadata']

    time.sleep(1)

    protocol_field = cfg['protocol'].split(',')
    valid_protocol=[]
    invalid_protocol_list=[]
    for protocol in protocol_field:
        if protocol == 'UDP' or protocol == 'TCP':
            valid_protocol.append(protocol)
        else:
            invalid_protocol_list.append(protocol)

    for invalid_protocol in invalid_protocol_list:
        log_callback = make_callback(
            fr"WARNING: \(\d+\): Ignored invalid value '{invalid_protocol}' for 'protocol",
            REMOTED_DETECTOR_PREFIX
        )
        wazuh_log_monitor.start(timeout=5, callback=log_callback,
                                error_message="Wazuh remoted didn't start as expected.")

    if len(valid_protocol) == 0:
        log_callback = make_callback(
            fr"WARNING: \(\d+\): Error getting protocol. Default value \(TCP\) will be used.",
            REMOTED_DETECTOR_PREFIX
        )
        wazuh_log_monitor.start(timeout=5, callback=log_callback,
                                error_message="Wazuh remoted didn't start as expected.")
    elif len(valid_protocol) == 1:
        log_callback = make_callback(
            fr"Started \(pid: \d+\). Listening on port {cfg['port']}\/{cfg['protocol']} \({cfg['connection']}\).",
            REMOTED_DETECTOR_PREFIX
        )
        wazuh_log_monitor.start(timeout=5, callback=log_callback,
                                error_message="Wazuh remoted didn't start as expected.")
    else:
        log_callback = make_callback(
            fr"Started \(pid: \d+\). Listening on port {cfg['port']}\/TCP,UDP \({cfg['connection']}\).",
            REMOTED_DETECTOR_PREFIX
        )
        wazuh_log_monitor.start(timeout=5, callback=log_callback,
                                error_message="Wazuh remoted didn't start as expected.")

    # Check that API query return the selected configuration
    for field in cfg.keys():
        api_answer = api.get_manager_configuration(section="remote", field=field)
        if field == 'protocol':
            array_protocol = np.array(cfg[field].split(","))
            assert (array_protocol == api_answer).all(), "Wazuh API answer different from introduced configuration"
        else:
            assert cfg[field] == api_answer, "Wazuh API answer different from introduced configuration"




""" 
parameters = [
    {'PROTOCOL': 'TCP', 'CONNECTION': 'Testing', 'PORT': '1514'}
]
metadata = [
    {'protocol': 'TCP', 'connection': 'Testing', 'port': '1514'}
]

configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)

def test_invalid_connection(get_configuration, configure_environment):
    """

    """
    truncate_file(LOG_FILE_PATH)
    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
    cfg = get_configuration['metadata']
    try:
        control_service('restart', daemon='wazuh-remoted')

    except:

        log_callback = make_callback(
            fr"ERROR: \(\d+\): Invalid value for element 'connection': {cfg['connection']}.",
            REMOTED_DETECTOR_PREFIX
        )
        wazuh_log_monitor.start(timeout=5, callback=log_callback,
                                error_message="Wazuh remoted didn't start as expected.")

        log_callback = make_callback(
            fr"ERROR: \(\d+\): Configuration error at '/var/ossec/etc/ossec.conf'.",
            REMOTED_DETECTOR_PREFIX
        )
        wazuh_log_monitor.start(timeout=5, callback=log_callback,
                                error_message="Wazuh remoted didn't start as expected.")

        log_callback = make_callback(
            fr"CRITICAL: \(\d+\): Configuration error at '/var/ossec/etc/ossec.conf'.",
            REMOTED_DETECTOR_PREFIX
        )
        wazuh_log_monitor.start(timeout=5, callback=log_callback,
                                error_message="Wazuh remoted didn't start as expected.")


parameters = [
    {'PROTOCOL': 'TCP', 'CONNECTION': 'secure', 'PORT': '99999'}
]
metadata = [
    {'protocol': 'TCP', 'connection': 'secure', 'port': '99999'}
]

configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)

def test_invalid_port(get_configuration, configure_environment):
    """

    """
    truncate_file(LOG_FILE_PATH)
    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
    cfg = get_configuration['metadata']
    try:
        control_service('restart', daemon='wazuh-remoted')

    except:

        log_callback = make_callback(
            fr"ERROR: \(\d+\): Invalid port number: '{cfg['port']}'.",
            REMOTED_DETECTOR_PREFIX
        )
        wazuh_log_monitor.start(timeout=5, callback=log_callback,
                                error_message="Wazuh remoted didn't start as expected.")

        log_callback = make_callback(
            fr"ERROR: \(\d+\): Configuration error at '/var/ossec/etc/ossec.conf'.",
            REMOTED_DETECTOR_PREFIX
        )
        wazuh_log_monitor.start(timeout=5, callback=log_callback,
                                error_message="Wazuh remoted didn't start as expected.")

        log_callback = make_callback(
            fr"CRITICAL: \(\d+\): Configuration error at '/var/ossec/etc/ossec.conf'.",
            REMOTED_DETECTOR_PREFIX
        )
        wazuh_log_monitor.start(timeout=5, callback=log_callback,
                                error_message="Wazuh remoted didn't start as expected.")
"""
