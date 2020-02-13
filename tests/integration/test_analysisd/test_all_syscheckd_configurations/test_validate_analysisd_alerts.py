# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import json
import os
import re
import time
from collections import defaultdict

import pytest
import yaml

from wazuh_testing.analysis import validate_analysis_alert_complex, callback_fim_alert
from wazuh_testing.tools import WAZUH_PATH, LOG_FILE_PATH, WAZUH_LOGS_PATH
from wazuh_testing.tools.monitoring import FileMonitor

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=2)]

# variables

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
alerts_json = os.path.join(WAZUH_LOGS_PATH, 'alerts', 'alerts.json')
messages_path = os.path.join(test_data_path, 'syscheck_events.yaml')

wdb_path = os.path.join(os.path.join(WAZUH_PATH, 'queue', 'db', 'wdb'))
analysis_path = os.path.join(os.path.join(WAZUH_PATH, 'queue', 'ossec', 'queue'))
monitored_sockets, receiver_sockets = None, None  # These variables will be set in the fixture create_unix_sockets
monitored_sockets_params = [(wdb_path, 'TCP')]
receiver_sockets_params = [(analysis_path, 'UDP')]
used_daemons = ['ossec-analysisd']
socket_path = analysis_path
analysis_monitor = None
wdb_monitor = None
events_dict = {}
alerts_list = []

with open(messages_path) as f:
    test_cases = yaml.safe_load(f)

# Syscheck variables
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
wazuh_alerts_monitor = None
n_directories = 0
directories_list = list()
testdir = 'testdir'
analysisd_injections_per_second = 200


@pytest.fixture(scope='module')
def generate_events_and_alerts(request):
    test_cases = getattr(request.module, 'test_cases')
    socket_controller = getattr(request.module, 'receiver_sockets')[0]
    events = defaultdict(dict)

    alert_monitor = FileMonitor(alerts_json)

    for test_case in test_cases:
        case = test_case['test_case'][0]
        event = (json.loads(re.match(r'(.*)syscheck:(.+)$', case['input']).group(2)))
        events[event['data']['path']].update({case['stage']: event})
        socket_controller.send([case['input']])
        time.sleep(1 / analysisd_injections_per_second)

    n_alerts = len(test_cases)
    alerts = alert_monitor.start(timeout=max(n_alerts * 0.001, 10), callback=callback_fim_alert,
                                 accum_results=n_alerts).result()

    setattr(request.module, 'alerts_list', alerts)
    setattr(request.module, 'events_dict', events)


@pytest.fixture(scope='module', params=range(len(test_cases)))
def get_alert(request):
    return alerts_list[request.param]


# fixtures

def test_validate_all_alerts(configure_mitm_environment_analysisd, create_unix_sockets, wait_for_analysisd_startup,
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
