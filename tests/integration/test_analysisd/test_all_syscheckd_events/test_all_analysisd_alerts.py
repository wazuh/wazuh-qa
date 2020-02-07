# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os

import pytest
import yaml

from wazuh_testing import global_parameters
from wazuh_testing.analysis import callback_analysisd_message
from wazuh_testing.tools import WAZUH_PATH, LOG_FILE_PATH, WAZUH_LOGS_PATH
from wazuh_testing.tools.monitoring import FileMonitor

pytestmark = [pytest.mark.linux, pytest.mark.win32, pytest.mark.tier(level=2)]

# variables

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
alerts_json = os.path.join(WAZUH_LOGS_PATH, 'alerts', 'alerts.json')
messages_path = os.path.join(test_data_path, 'syscheck_events.yaml')
wazuh_alerts_monitor = FileMonitor(alerts_json)

wdb_path = os.path.join(os.path.join(WAZUH_PATH, 'queue', 'db', 'wdb'))
analysis_path = os.path.join(os.path.join(WAZUH_PATH, 'queue', 'ossec', 'queue'))
monitored_sockets, receiver_sockets = None, None  # These variables will be set in the fixture create_unix_sockets
monitored_sockets_params = [(wdb_path, 'TCP')]
# monitored_sockets_params = []
receiver_sockets_params = [(analysis_path, 'UDP')]
used_daemons = ['ossec-analysisd', 'wazuh-db']

with open(messages_path) as f:
    test_cases = yaml.safe_load(f)

# Syscheck variables
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
n_directories = 0
directories_list = list()
testdir = 'testdir'


# fixtures

@pytest.fixture(scope='module')
def wait_for_analysisd_startup(request):
    def callback_analysisd_startup(line):
        if 'Input message handler thread started.' in line:
            return line
        return None

    log_monitor = getattr(request.module, 'wazuh_log_monitor')
    log_monitor.start(timeout=30, callback=callback_analysisd_startup)


# tests[test_cases[4097], test_cases[8192]


@pytest.mark.parametrize('test_case',
                         [test_case['test_case'] for test_case in test_cases],
                         ids=[test_case['name'] for test_case in test_cases])
def test_validate_all_alerts(configure_environment_standalone_daemons, create_unix_sockets, wait_for_analysisd_startup,
                             test_case: list):
# def test_validate_all_alerts(set_syscheck_config, configure_syscheck_environment, generate_analysisd_yaml):
    """ Checks the event messages handling by analysisd.

    The variable messages is a yaml file that contains the input and the expected output for every test case.
    The function validate_analysis_integrity_state is a function responsible for checking that the output follows a
    certain jsonschema.

    """

    # for stage in test_case:
        # expected = callback_analysisd_message(stage['output'])
        # receiver_sockets[0].send([stage['input']])
        # response = monitored_sockets[0].start(timeout=global_parameters.default_timeout,
        #                                       callback=callback_analysisd_message).result()
        # assert response == expected, 'Failed test case stage {}: {}'.format(test_case.index(stage) + 1, stage['stage'])
        # alert = wazuh_alerts_monitor.start(timeout=2*global_parameters.default_timeout,
        #                                    callback=callback_fim_alert).result()
        # event = json.loads(re.match(r'(.*)syscheck:(.+)$', stage['input']).group(2))
        # validate_analysis_alert_complex(alert, event)
