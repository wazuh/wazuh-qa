# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import json
import os
import re
import time
from collections import defaultdict

import pytest

from wazuh_testing.analysis import callback_fim_alert
from wazuh_testing.tools import WAZUH_LOGS_PATH
from wazuh_testing.tools.monitoring import FileMonitor, ManInTheMiddle, QueueMonitor
from wazuh_testing.tools.services import control_service, check_daemon_status

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')


@pytest.fixture(scope='module')
def wait_for_analysisd_startup(request):
    """Wait until analysisd has begun and alerts.json is created."""
    def callback_analysisd_startup(line):
        if 'Input message handler thread started.' in line:
            return line
        return None

    log_monitor = getattr(request.module, 'wazuh_log_monitor')
    log_monitor.start(timeout=30, callback=callback_analysisd_startup)


@pytest.fixture(scope='module')
def configure_mitm_environment_analysisd(request):
    """Use MITM to replace analysisd and wazuh-db sockets."""
    def remove_logs():
        for root, dirs, files in os.walk(WAZUH_LOGS_PATH):
            for file in files:
                os.remove(os.path.join(root, file))

    analysis_path = getattr(request.module, 'analysis_path')
    wdb_path = getattr(request.module, 'wdb_path')

    # Stop wazuh-service and ensure all daemons are stopped
    control_service('stop')
    check_daemon_status(running=False)
    remove_logs()

    control_service('start', daemon='wazuh-db', debug_mode=True)
    check_daemon_status(running=True, daemon='wazuh-db')

    mitm_wdb = ManInTheMiddle(socket_path=wdb_path)
    wdb_queue = mitm_wdb.queue
    mitm_wdb.start()

    control_service('start', daemon='ossec-analysisd', debug_mode=True)
    check_daemon_status(running=True, daemon='ossec-analysisd')

    mitm_analysisd = ManInTheMiddle(socket_path=analysis_path, mode='UDP')
    analysisd_queue = mitm_analysisd.queue
    mitm_analysisd.start()

    analysis_monitor = QueueMonitor(queue_item=analysisd_queue)
    wdb_monitor = QueueMonitor(queue_item=wdb_queue)

    setattr(request.module, 'analysis_monitor', analysis_monitor)
    setattr(request.module, 'wdb_monitor', wdb_monitor)

    yield

    mitm_analysisd.shutdown()
    mitm_wdb.shutdown()

    for daemon in ['wazuh-db', 'ossec-analysisd']:
        control_service('stop', daemon=daemon)
        check_daemon_status(running=False, daemon=daemon)

    control_service('start')


@pytest.fixture(scope='module')
def generate_events_and_alerts(request):
    """Read the specified yaml and generate every event and alert using the input from every test case.

    Alerts are saved in a list and events have the following structure:
        {
            'path':
            {
                'Added': event
                'Modified': event
                'Deleted': event
            }
            ...
        }
    """
    alerts_json = os.path.join(WAZUH_LOGS_PATH, 'alerts', 'alerts.json')
    test_cases = getattr(request.module, 'test_cases')
    socket_controller = getattr(request.module, 'receiver_sockets')[0]
    events = defaultdict(dict)
    ips = getattr(request.module, 'analysisd_injections_per_second')

    alert_monitor = FileMonitor(alerts_json)

    for test_case in test_cases:
        case = test_case['test_case'][0]
        event = (json.loads(re.match(r'(.*)syscheck:(.+)$', case['input']).group(2)))
        events[event['data']['path']].update({case['stage']: event})
        socket_controller.send([case['input']])
        time.sleep(1 / ips)

    n_alerts = len(test_cases)
    time.sleep(3)
    alerts = alert_monitor.start(timeout=max(n_alerts * 0.001, 15), callback=callback_fim_alert,
                                 accum_results=n_alerts).result()

    setattr(request.module, 'alerts_list', alerts)
    setattr(request.module, 'events_dict', events)
