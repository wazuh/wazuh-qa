'''
copyright: Copyright (C) 2015-2023, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check that the events are correctly handled by the engine module.

components:
    - engine

suite: test_events

targets:
    - manager

daemons:
    - wazuh-engine

os_platform:
    - linux

os_version:
    - Ubuntu Focal

references:
    - https://github.com/wazuh/wazuh/issues/11334

tags:
    - engine
    - events
'''
import os
import pytest


from wazuh_testing.tools.configuration import get_test_cases_data
from wazuh_testing.modules.engine import event_monitor as evm
from wazuh_testing.modules import engine


# Reference paths
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases')

# Configuration and cases data
t1_cases_path = os.path.join(TEST_CASES_PATH, 'cases_engine_events.yaml')

# Engine events configurations
t1_configuration_parameters, t1_configuration_metadata, t1_case_ids = get_test_cases_data(t1_cases_path)


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('events_data', t1_configuration_metadata, ids=t1_case_ids)
def test_receiving_events_socket(events_data, truncate_engine_files, restart_engine_function):
    '''
    description: Check that every event sent through the engine's queue socket is correctly received and stored in the
                 expected log files.

    test_phases:
        - Clean the log and alert files
        - Restart the wazuh-engine
        - Send each case's log through the queue socket
        - Verify that each case's log has been received

    wazuh_min_version: 5.0.0

    tier: 0

    parameters:
        - events_data:
            type: dict
            brief: events' metadata.
        - truncate_engine_files:
            type: fixture
            brief: Clean the alerts/logs before and after running the tests.
        - restart_engine_function:
            type: fixture
            brief: Restart the wazuh-engine daemon.

    assertions:
        - Verify that after sending events we are allowed to catch them within the engine alerts.

    input_description:
        - The `cases_engine_events.yaml` file provides the module configuration for this test.

    expected_output:
        - Every item within the metadata.engine_outputs object should be placed within the expected log files.
    '''
    # Send the messages through the queue socket to the engine
    engine.send_events_to_engine_dgram(events=events_data['events'])

    # Verify that sent messages appear within the alerts
    for expected_output in events_data['engine_outputs']:
        evm.check_engine_event_output(event=expected_output)
