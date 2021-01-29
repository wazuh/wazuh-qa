# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest
import yaml
from wazuh_testing.analysis import validate_analysis_alert_complex
from wazuh_testing.tools import WAZUH_PATH, LOG_FILE_PATH, ALERT_FILE_PATH
from wazuh_testing.tools.monitoring import ManInTheMiddle

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=2), pytest.mark.server]

# Configurations

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
messages_path = os.path.join(test_data_path, 'syscheck_events.yaml')
with open(messages_path) as f:
    test_cases = yaml.safe_load(f)

# Variables

log_monitor_paths = [LOG_FILE_PATH, ALERT_FILE_PATH]
analysis_path = os.path.join(os.path.join(WAZUH_PATH, 'queue', 'ossec', 'queue'))

receiver_sockets_params = [(analysis_path, 'AF_UNIX', 'UDP')]

mitm_analysisd = ManInTheMiddle(address=analysis_path, family='AF_UNIX', connection_protocol='UDP')
# monitored_sockets_params is a List of daemons to start with optional ManInTheMiddle to monitor
# List items -> (wazuh_daemon: str,(
#                mitm: ManInTheMiddle
#                daemon_first: bool))
# Example1 -> ('wazuh-clusterd', None)              Only start wazuh-clusterd with no MITM
# Example2 -> ('wazuh-clusterd', (my_mitm, True))   Start MITM and then wazuh-clusterd
monitored_sockets_params = [('wazuh-db', None, None), ('wazuh-analysisd', mitm_analysisd, True)]

receiver_sockets, monitored_sockets, log_monitors = None, None, None  # Set in the fixtures

events_dict = {}
alerts_list = []
analysisd_injections_per_second = 200


# Fixtures


@pytest.fixture(scope='module', params=range(len(test_cases)))
def get_alert(request):
    return alerts_list[request.param]


# Tests


def test_validate_all_linux_alerts(configure_sockets_environment, connect_to_sockets_module, wait_for_analysisd_startup,
                                   generate_events_and_alerts, get_alert):
    """Check the event messages handling by analysisd.

    The variable `test_case` is a yaml file that contains the input and the expected output for every test case.
    The function validate_analysis_integrity_state is a function responsible for checking that the output follows a
    certain jsonschema.
    """
    alert = get_alert
    path = alert['syscheck']['path']
    mode = alert['syscheck']['event'].title()
    validate_analysis_alert_complex(alert, events_dict[path][mode])
