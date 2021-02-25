# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
import time
import numpy as np
import wazuh_testing.api as api
from wazuh_testing.tools import LOG_FILE_PATH

from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.monitoring import make_callback, REMOTED_DETECTOR_PREFIX
from wazuh_testing.tools.services import control_service

# Marks
pytestmark = pytest.mark.tier(level=0)

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_basic_configuration.yaml')

parameters = [
    {'PROTOCOL': 'UDP', 'CONNECTION': 'secure', 'PORT': '1514'},
    {'PROTOCOL': 'UDP', 'CONNECTION': 'syslog', 'PORT': '514'},
    {'PROTOCOL': 'TCP', 'CONNECTION': 'syslog', 'PORT': '514'},
    {'PROTOCOL': 'TCP', 'CONNECTION': 'secure', 'PORT': '1514'},
    {'PROTOCOL': 'TCP,UDP', 'CONNECTION': 'secure', 'PORT': '1514'},
    {'PROTOCOL': 'TCP,UDP', 'CONNECTION': 'syslog', 'PORT': '514'},
    {'PROTOCOL': 'UDP,TCP', 'CONNECTION': 'secure', 'PORT': '1514'},
    {'PROTOCOL': 'UDP,TCP', 'CONNECTION': 'syslog', 'PORT': '514'}
]
metadata = [
    {'protocol': 'UDP', 'connection': 'secure', 'port': '1514'},
    {'protocol': 'UDP', 'connection': 'syslog', 'port': '514'},
    {'protocol': 'TCP', 'connection': 'syslog', 'port': '514'},
    {'protocol': 'TCP', 'connection': 'secure', 'port': '1514'},
    {'protocol': 'TCP,UDP', 'connection': 'secure', 'port': '1514'},
    {'protocol': 'TCP,UDP', 'connection': 'syslog', 'port': '514'},
    {'protocol': 'UDP,TCP', 'connection': 'secure', 'port': '1514'},
    {'protocol': 'UDP,TCP', 'connection': 'syslog', 'port': '514'}
]

configurations = load_wazuh_configurations(configurations_path, "test_basic_configuration_connection", params=parameters, metadata=metadata)
configuration_ids = [f"{x['PROTOCOL']}_{x['CONNECTION']}_{x['PORT']}" for x in parameters]


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_connection(get_configuration, configure_environment):
    """
    Checks that "connection" option could be configured as "secure" or "syslog" without errors
        this option specifies a type of incoming connection to accept: secure or syslog.

    Checks that the API answer for manager connection coincides with the option selected on ossec.conf
    """

    truncate_file(LOG_FILE_PATH)
    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

    control_service('restart', daemon='wazuh-remoted')

    cfg = get_configuration['metadata']

    time.sleep(1)

    log_message_connection = "Started \(pid: \d+\). Listening on port {cfg['port']}\/{cfg['protocol']} \({cfg['connection']}\)."

    if (cfg['protocol'] == 'TCP,UDP' or cfg['protocol'] == 'UDP,TCP') and cfg['connection'] == 'syslog':
        log_callback = make_callback(
            fr"WARNING: \(\d+\): Only secure connection supports TCP and UDP at the same time. Default value \(TCP\) will be used.",
            REMOTED_DETECTOR_PREFIX
        )
        wazuh_log_monitor.start(timeout=5, callback=log_callback,
                                error_message="Wazuh remoted didn't start as expected.")
        log_message_connection = "Started \(pid: \d+\). Listening on port {cfg['port']}\/TCP \({cfg['connection']}\)."

    log_callback = make_callback(
        fr"{log_message_connection}",
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

