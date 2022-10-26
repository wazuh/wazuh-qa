
import os
import pytest
import time

from wazuh_testing import LOG_FILE_PATH
from wazuh_testing import T_10
from wazuh_testing.tools.configuration import load_configuration_template, get_test_cases_data
from wazuh_testing.tools.run_simulator import syslog_simulator
from wazuh_testing.tools.thread_executor import ThreadExecutor
from wazuh_testing.modules.analysisd import event_monitor as evm


# Reference paths
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, 'configuration_template', 'logging_test_module')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases', 'logging_test_module')
SYSLOG_SIMULATOR_START_TIME = 2
local_internal_options = {'analysisd.debug': 2}


# ------------------------------------------------ TEST_DROPPING_EVENTS ------------------------------------------------
# Configuration and cases data
t1_configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_dropping_events.yaml')
t1_cases_path = os.path.join(TEST_CASES_PATH, 'cases_dropping_events.yaml')

# Dropping event test configurations (t1)
t1_configuration_parameters, t1_configuration_metadata, t1_case_ids = get_test_cases_data(t1_cases_path)
t1_configurations = load_configuration_template(t1_configurations_path, t1_configuration_parameters,
                                                t1_configuration_metadata)


@pytest.mark.tier(level=1)
@pytest.mark.parametrize('configuration, metadata', zip(t1_configurations, t1_configuration_metadata), ids=t1_case_ids)
def test_dropping_events(configuration, metadata, load_wazuh_basic_configuration, set_wazuh_configuration,
                         configure_local_internal_options_function, truncate_monitored_files,
                         restart_wazuh_daemon_function):
    """
    description: Check that after the event analysis block, if the events queue is full, the events are dropped.

    test_phases:
        - setup:
            - Load Wazuh light configuration.
            - Apply ossec.conf configuration changes according to the configuration template and use case.
            - Apply custom settings in local_internal_options.conf.
            - Truncate wazuh logs.
            - Restart wazuh-manager service to apply configuration changes.
        - test:
            - Send events until queue is full and dropping events.
            - Check that "Queues are full and no EPS credits, dropping events" log appears in WARNING mode.
            - Wait timeframe to release the events queue usage and send an event.
            - Check that "Queues back to normal and EPS credits, no dropping events" log appears in INFO mode.
            - Send events until queue is full and dropping events.
            - Check that "Queues are full and no EPS credits, dropping events" log appears in DEBUG mode.
            - Wait timeframe to release the events queue usage and send an event.
            - Check that "Queues back to normal and EPS credits, no dropping events" log appears in DEBUG mode.
        - tierdown:
            - Truncate wazuh logs.
            - Restore initial configuration, both ossec.conf and local_internal_options.conf.

    wazuh_min_version: 4.4.0

    parameters:
        - configuration:
            type: dict
            brief: Get configurations from the module.
        - metadata:
            type: dict
            brief: Get metadata from the module.
        - load_wazuh_basic_configuration:
            type: fixture
            brief: Load basic wazuh configuration.
        - set_wazuh_configuration:
            type: fixture
            brief: Apply changes to the ossec.conf configuration.
        - configure_local_internal_options_function:
            type: fixture
            brief: Apply changes to the local_internal_options.conf configuration.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate wazuh logs.
        - restart_wazuh_daemon_function:
            type: fixture
            brief: Restart the wazuh service.

    assertions:
        - Check that "Queues are full and no EPS credits, dropping events" log appears in WARNING mode.
        - Check that "Queues back to normal and EPS credits, no dropping events" log appears in INFO mode.
        - Check that "Queues are full and no EPS credits, dropping events" log appears in DEBUG mode.
        - Check that "Queues back to normal and EPS credits, no dropping events" log appears in DEBUG mode.

    input_description:
        - The `configuration_dropping_events.yaml` file provides the module configuration for this test.
        - The `cases_dropping_events.yaml` file provides the test cases.
    """
    # Set syslog simulator parameters according to the use case data
    syslog_simulator_parameters = {'address': metadata['address'], 'port': metadata['port'],
                                   'protocol': metadata['protocol'], 'eps': metadata['eps'],
                                   'messages_number': metadata['messages_number']}

    # Run syslog simulator thread for sending events
    syslog_simulator_thread = ThreadExecutor(syslog_simulator, {'parameters': syslog_simulator_parameters})
    syslog_simulator_thread.start()

    # Check for dropping events WARNING log
    evm.check_queues_are_full_and_no_eps_credits_log(log_level='WARNING', timeout=T_10)

    # Wait until syslog simulator ends
    syslog_simulator_thread.join()

    # Wait until the next timeframe to release elements from the queue (as they will be processed)
    time.sleep(metadata['timeframe'])

    # Send 1 event more
    syslog_simulator_parameters.update({'messages_number': 1, 'eps': 1})
    syslog_simulator_thread = ThreadExecutor(syslog_simulator, {'parameters': syslog_simulator_parameters})
    syslog_simulator_thread.start()

    # Check for stop dropping events INFO log
    evm.check_stop_dropping_events_and_credits_available_log(log_level='INFO', timeout=T_10)

    # Wait until syslog simulator ends
    syslog_simulator_thread.join()

    # Stage 2: If we continue causing this situation, the following logs must be in DEBUG

    # Run syslog simulator thread for sending events
    syslog_simulator_parameters.update({'messages_number': metadata['messages_number'], 'eps': metadata['eps']})
    syslog_simulator_thread = ThreadExecutor(syslog_simulator, {'parameters': syslog_simulator_parameters})
    syslog_simulator_thread.start()

    # Check for dropping events DEBUG log
    evm.check_queues_are_full_and_no_eps_credits_log(log_level='DEBUG', timeout=T_10)

    # Wait until syslog simulator ends
    syslog_simulator_thread.join()

    # Wait until the next timeframe to release elements from the queue (as they will be processed)
    time.sleep(metadata['timeframe'])

    # Send 1 event more
    syslog_simulator_parameters.update({'messages_number': 1, 'eps': 1})
    syslog_simulator_thread = ThreadExecutor(syslog_simulator, {'parameters': syslog_simulator_parameters})
    syslog_simulator_thread.start()

    # Check for stop dropping events DEBUG log
    evm.check_stop_dropping_events_and_credits_available_log(log_level='DEBUG', timeout=T_10)

    # Wait until syslog simulator ends
    syslog_simulator_thread.join()
