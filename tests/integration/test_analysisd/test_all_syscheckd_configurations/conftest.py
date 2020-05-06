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
from wazuh_testing.tools.monitoring import FileMonitor


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
        socket_controller.send(case['input'])
        time.sleep(1 / ips)

    n_alerts = len(test_cases)
    time.sleep(3)
    alerts = alert_monitor.start(timeout=max(n_alerts * 0.001, 15), callback=callback_fim_alert,
                                 accum_results=n_alerts).result()

    setattr(request.module, 'alerts_list', alerts)
    setattr(request.module, 'events_dict', events)
