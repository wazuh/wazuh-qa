import os
import pytest
import time
import re
from math import ceil
from copy import deepcopy

from wazuh_testing.tools.configuration import load_configuration_template, get_test_cases_data
from wazuh_testing import ARCHIVES_LOG_PATH
from wazuh_testing.modules.analysisd import event_monitor as evm
from wazuh_testing.tools import file
from wazuh_testing.modules.analysisd import QUEUE_EVENTS_SIZE, ANALYSISD_ONE_THREAD_CONFIG
from wazuh_testing.scripts.syslog_simulator import DEFAULT_MESSAGE_SIZE
from wazuh_testing.tools.run_simulator import syslog_simulator
from wazuh_testing.tools.thread_executor import ThreadExecutor

# Reference paths
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, 'configuration_template', 'event_processing_test_module')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases', 'event_processing_test_module')
SYSLOG_SIMULATOR_START_TIME = 2
local_internal_options = {'wazuh_modules.debug': '2', 'monitord.rotate_log': '0', 'analysisd.state_interval': '1'}

# --------------------------------------------------- TEST_LIMITATION --------------------------------------------------
# Configuration and cases data
t1_configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_limitation.yaml')
t1_cases_path = os.path.join(TEST_CASES_PATH, 'cases_limitation.yaml')

# Limitation test configurations (t1)
t1_configuration_parameters, t1_configuration_metadata, t1_case_ids = get_test_cases_data(t1_cases_path)
t1_configurations = load_configuration_template(t1_configurations_path, t1_configuration_parameters,
                                                t1_configuration_metadata)

# ---------------------------------------- TEST_QUEUEING_EVENTS_AFTER_LIMITATION ---------------------------------------
# Configuration and cases data
t2_configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_queueing_events_after_limitation.yaml')
t2_cases_path = os.path.join(TEST_CASES_PATH, 'cases_queueing_events_after_limitation.yaml')

# Queing event test configurations (t2)
t2_configuration_parameters, t2_configuration_metadata, t2_case_ids = get_test_cases_data(t2_cases_path)
t2_configurations = load_configuration_template(t2_configurations_path, t2_configuration_parameters,
                                                t2_configuration_metadata)

# --------------------------------------- TEST_DROPPING_EVENTS_WHEN_QUEUE_IS_FULL --------------------------------------
# Configuration and cases data
t3_configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_drop_events_when_queue_is_full.yaml')
t3_cases_path = os.path.join(TEST_CASES_PATH, 'cases_drop_events_when_queue_is_full.yaml')

# Dropping events when queue is full test configurations (t3)
t3_configuration_parameters, t3_configuration_metadata, t3_case_ids = get_test_cases_data(t3_cases_path)
t3_configurations = load_configuration_template(t3_configurations_path, t3_configuration_parameters,
                                                t3_configuration_metadata)

# ------------------------------------ TEST_PROCESSING_EVENTS_IN_ORDER_SINGLE_THREAD -----------------------------------
# Configuration and cases data
t4_configurations_path = os.path.join(CONFIGURATIONS_PATH,
                                      'configuration_processing_events_in_order_single_thread.yaml')
t4_cases_path = os.path.join(TEST_CASES_PATH, 'cases_processing_events_in_order_single_thread.yaml')

# Processing events in order single thread test configurations (t4)
t4_configuration_parameters, t4_configuration_metadata, t4_case_ids = get_test_cases_data(t4_cases_path)
t4_configurations = load_configuration_template(t4_configurations_path, t4_configuration_parameters,
                                                t4_configuration_metadata)
t4_local_internal_options = {'wazuh_modules.debug': '2', 'monitord.rotate_log': '0', 'analysisd.state_interval': '1'}
t4_local_internal_options.update(ANALYSISD_ONE_THREAD_CONFIG)

# ------------------------------------ TEST_PROCESSING_EVENTS_IN_ORDER_MULTI_THREAD ------------------------------------
# Configuration and cases data
t5_configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_processing_events_in_order_multi_thread.yaml')
t5_cases_path = os.path.join(TEST_CASES_PATH, 'cases_processing_events_in_order_multi_thread.yaml')

# Processing events in order multi thread test configurations (t5)
t5_configuration_parameters, t5_configuration_metadata, t5_case_ids = get_test_cases_data(t5_cases_path)
t5_configurations = load_configuration_template(t5_configurations_path, t5_configuration_parameters,
                                                t5_configuration_metadata)


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('configuration, metadata', zip(t1_configurations, t1_configuration_metadata), ids=t1_case_ids)
def test_limitation(configuration, metadata, load_wazuh_basic_configuration, set_wazuh_configuration,
                    configure_local_internal_options_function, truncate_monitored_files, restart_wazuh_daemon_function):
    """
    description: Check if after passing the event processing limit, the processing is stopped until the next timeframe.

    test_phases:
        - setup:
            - Load Wazuh light configuration.
            - Apply ossec.conf configuration changes according to the configuration template and use case.
            - Apply custom settings in local_internal_options.conf.
            - Truncate wazuh logs.
            - Restart wazuh-manager service to apply configuration changes.
        - test:
            - Start the event simulator and check that the events are being received and analyzed.
            - Wait until the event limit is reached and check that the events are still being received but not
              processed.
            - Wait until the next analysis period (next timeframe) and check that events are still being
              processed, in this case the queued ones.
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
        - Check that events are received when expected.
        - Check that events are processed when expected.
        - Check that events are still received when expected.
        - Check that no events are processed due to blocking.
        - Check that events are still processed after blocking.

    input_description:
        - The `configuration_limitation` file provides the module configuration for this test.
        - The `cases_limitation` file provides the test cases.
    """
    # Set syslog simulator parameters according to the use case data
    syslog_simulator_parameters = {'address': metadata['address'], 'port': metadata['port'],
                                   'protocol': metadata['protocol'], 'eps': metadata['eps'],
                                   'messages_number': metadata['messages_number']}

    # Run syslog simulator thread
    syslog_simulator_thread = ThreadExecutor(syslog_simulator, {'parameters': syslog_simulator_parameters})
    syslog_simulator_thread.start()
    waited_simulator_time = 0

    # Wait until syslog simulator is started
    time.sleep(SYSLOG_SIMULATOR_START_TIME)

    # Get analysisd stats
    analysisd_state = evm.get_analysisd_state()
    events_received = int(analysisd_state['events_received'])
    events_processed = int(analysisd_state['events_processed'])

    # Check that wazuh-manager is processing syslog events
    assert events_received > 0, '(0): No events are being received when it is expected'
    assert events_processed > 0, 'No events are being processed when it is expected'

    # Wait for the event non-processing phase to arrive (limit reached)
    waiting_limit_time = ceil((metadata['maximum'] * metadata['timeframe']) / metadata['eps']) + 1  # Offset 1s
    time.sleep(waiting_limit_time)
    waited_simulator_time += waiting_limit_time

    # Get analysisd stats in limitation stage
    analysisd_state = evm.get_analysisd_state()
    events_received = int(analysisd_state['events_received'])
    events_processed = int(analysisd_state['events_processed'])
    expected_processed_events = metadata['maximum'] * metadata['timeframe']

    # Check that the wazuh-manager is receiving events but it is not processing them due to the limitation
    assert events_received > 0, '(1): No events are being received when it is expected'
    assert events_processed == expected_processed_events, f"Events are being processed when the limit has been " \
                                                          f"reached. {events_processed} != {expected_processed_events}"

    # Wait until the limited timeframe has elapsed
    time.sleep(metadata['timeframe'] + 1 - waited_simulator_time)  # Offset 1s

    # Get analysisd stats in limitation stage
    analysisd_state = evm.get_analysisd_state()
    events_processed = int(analysisd_state['events_processed'])

    # Check whether events continue to be processed after blocking
    assert events_processed > 0, 'Event processing has not been continued after blocking'

    # Wait until syslog simulator ends
    syslog_simulator_thread.join()


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('configuration, metadata', zip(t2_configurations, t2_configuration_metadata), ids=t2_case_ids)
def test_queueing_events_after_limitation(configuration, metadata, load_wazuh_basic_configuration,
                                          set_wazuh_configuration, configure_local_internal_options_function,
                                          truncate_monitored_files, restart_wazuh_daemon_function):
    """
    description: Check if after stopping processing events (due to limit reached), the received events are stored in
        the events queue if it is not full.

    test_phases:
        - setup:
            - Load Wazuh light configuration.
            - Apply ossec.conf configuration changes according to the configuration template and use case.
            - Apply custom settings in local_internal_options.conf.
            - Truncate wazuh logs.
            - Restart wazuh-manager service to apply configuration changes.
        - test:
            - Check that the initial events queue usage rate is 0%.
            - Calculate when the limit of processed events is reached, waits a few seconds for events to be stored in
              the events queue and takes a sample of the usage to check that it is higher than 0%.
            - Wait a few seconds and takes a second sample again, to check that the events queue usage is higher than
              the first sample.
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
        - Check that the queue usage at startup is 0%.
        - Check that the queue usage grows after stopping processing events.
        - Check that the queue usage continues to grow after stopping processing events.

    input_description:
        - The `configuration_queueing_events_after_limitation` file provides the module configuration for this test.
        - The `cases_queueing_events_after_limitation` file provides the test cases.
    """
    # Get initial queue usage
    analysisd_state = evm.get_analysisd_state()
    event_queue_usage = float(analysisd_state['event_queue_usage'])

    # Check that there are no events in the queue
    assert event_queue_usage == 0.0, 'The initial events queue is not at 0%'

    # Set syslog simulator parameters according to the use case data
    syslog_simulator_parameters = {'address': metadata['address'], 'port': metadata['port'],
                                   'protocol': metadata['protocol'], 'eps': metadata['eps'],
                                   'messages_number': metadata['messages_number']}

    # Run syslog simulator thread
    syslog_simulator_thread = ThreadExecutor(syslog_simulator, {'parameters': syslog_simulator_parameters})
    syslog_simulator_thread.start()

    # Wait for the event non-processing stage (limit reached)
    waiting_limit_time = ceil((metadata['maximum'] * metadata['timeframe']) / metadata['eps']) + \
        SYSLOG_SIMULATOR_START_TIME
    time.sleep(waiting_limit_time)

    # Get queue usage in limitation stage
    analysisd_state = evm.get_analysisd_state()
    event_queue_usage_sample_1 = float(analysisd_state['event_queue_usage'])

    # Check that received and unprocessed events are being queued
    assert event_queue_usage_sample_1 > 0.0, 'Events received after processing limitation are not being queued'

    # Wait a few more seconds before passing the timeframe
    waiting_time_sample_2 = ceil((metadata['timeframe'] - waiting_limit_time) / 2)
    time.sleep(waiting_time_sample_2)

    # Get queue usage in limitation stage
    analysisd_state = evm.get_analysisd_state()
    event_queue_usage_sample_2 = float(analysisd_state['event_queue_usage'])

    # Check that events received and not processed are still being queued
    assert event_queue_usage_sample_2 > event_queue_usage_sample_1, 'Events queue has not grown as expected during ' \
                                                                    'event limitation'
    # Wait until syslog simulator ends
    syslog_simulator_thread.join()


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('configuration, metadata', zip(t3_configurations, t3_configuration_metadata), ids=t3_case_ids)
def test_dropping_events_when_queue_is_full(configuration, metadata, load_wazuh_basic_configuration,
                                            set_wazuh_configuration, configure_local_internal_options_function,
                                            truncate_monitored_files, restart_wazuh_daemon_function):
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
            - Check that the initial queue usage rate is 0%.
            - Calculate when the event analysis blocking phase is expected and the queue is full, then it measures the
              use of the event queue to check that it is 100%, and that the received events are being dropped.
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
        - Check that the initial queue is at 0%.
        - Check that after the event analysis block and the queue is full, events are still being received.
        - Check that no events are processed when it is expected.
        - Check that the event queue usage is at 100% when it is expected.
        - Check that all events received are being dropped because the queue is full.

    input_description:
        - The `configuration_dropping_events_when_queue_is_full` file provides the module configuration for this test.
        - The `cases_dropping_events_when_queue_is_full` file provides the test cases.
    """
    # Get initial queue usage
    analysisd_state = evm.get_analysisd_state()
    event_queue_usage = float(analysisd_state['event_queue_usage'])

    # Check that there are no events in the queue
    assert event_queue_usage == 0.0, 'The initial events queue is not at 0%'

    # Set syslog simulator parameters according to the use case data
    syslog_simulator_parameters = {'address': metadata['address'], 'port': metadata['port'],
                                   'protocol': metadata['protocol'], 'eps': metadata['eps'],
                                   'messages_number': metadata['messages_number']}

    # Run syslog simulator thread
    syslog_simulator_thread = ThreadExecutor(syslog_simulator, {'parameters': syslog_simulator_parameters})
    syslog_simulator_thread.start()

    # Calculate the non-processing stage (limit reached)
    waiting_limit_time = ceil((metadata['maximum'] * metadata['timeframe']) / metadata['eps']) + \
        SYSLOG_SIMULATOR_START_TIME

    # Calculate the stage when the events queue is full (offset 4 sec to check all received-dropped events)
    waiting_time_queue_is_full = waiting_limit_time + ((QUEUE_EVENTS_SIZE / DEFAULT_MESSAGE_SIZE) / metadata['eps']) + 4
    time.sleep(waiting_time_queue_is_full)

    # Get analysisd stats
    analysisd_state = evm.get_analysisd_state()
    event_queue_usage = float(analysisd_state['event_queue_usage'])
    events_dropped = float(analysisd_state['events_dropped'])
    events_received = int(analysisd_state['events_received'])
    events_processed = int(analysisd_state['events_processed'])
    expected_processed_events = metadata['maximum'] * metadata['timeframe']

    # Check that events are received, not processed and that they are dropped when the queue is full
    assert events_received > 0, ' No events are being received when it is expected'
    assert events_processed == expected_processed_events, 'Events are being processed when they are' \
                                                          ' not expected (due to the limit)'
    assert event_queue_usage == 1.0, 'The events queue is not full as expected'
    assert events_dropped > 10000, 'No events are being dropped even though the queue is full'

    # Wait until syslog simulator ends
    syslog_simulator_thread.join()


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('configuration, metadata', zip(t4_configurations, t4_configuration_metadata), ids=t4_case_ids)
@pytest.mark.parametrize('configure_local_internal_options_function', [t4_local_internal_options], indirect=True)
def test_event_processing_in_order_single_thread(configuration, metadata, load_wazuh_basic_configuration,
                                                 set_wazuh_configuration, configure_local_internal_options_function,
                                                 truncate_event_logs, restart_wazuh_daemon_function):
    """
    description: Check that events are processed in order according to the position within the queue, and
        that events that are being received during the blocking phase are being added to the end of the queue when
        using single-thread processing.

    test_phases:
        - setup:
            - Load Wazuh light configuration.
            - Apply ossec.conf configuration changes according to the configuration template and use case.
            - Apply custom settings in local_internal_options.conf.
            - Truncate wazuh event logs.
            - Restart wazuh-manager service to apply configuration changes.
        - test:
            - Send a batch of identified events.
            - Wait a few seconds, then send another batch of identified events.
            - Wait until all events are processed.
            - Read the event log (archives.log) and check that the events have been processed in the expected order.
        - tierdown:
            - Truncate wazuh event logs.
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
        - truncate_event_logs:
            type: fixture
            brief: Truncate wazuh event logs.
        - restart_wazuh_daemon_function:
            type: fixture
            brief: Restart the wazuh service.

    assertions:
        - Check that all expected events have been stored in the archives.log.
        - Check that all events have been generated in the archives.log according to the expected order.

    input_description:
        - The `configuration_event_processing_in_order_single_thread` file provides the module configuration for this
          test.
        - The `cases_event_processing_in_order_single_thread` file provides the test cases.
    """
    # Set syslog simulator parameters according to the use case data
    syslog_simulator_parameters_1 = {'address': metadata['address'], 'port': metadata['port'],
                                     'protocol': metadata['protocol'], 'eps': metadata['eps'],
                                     'messages_number': metadata['messages_number_1'], 'message': metadata['message'],
                                     'numbered_messages': metadata['numbered_messages']}

    # Run syslog simulator thread
    syslog_simulator_thread_1 = ThreadExecutor(syslog_simulator, {'parameters': syslog_simulator_parameters_1})
    syslog_simulator_thread_1.start()

    # Wait until the first processing interval has passed.
    waiting_time = metadata['timeframe']
    time.sleep(waiting_time)

    # Run syslog simulator to send new events when events sent previously still have to be processed
    # (they are in the queue)
    syslog_simulator_parameters_2 = {'address': metadata['address'], 'port': metadata['port'],
                                     'protocol': metadata['protocol'], 'eps': metadata['eps'],
                                     'messages_number': metadata['messages_number_2'], 'message': metadata['message'],
                                     'numbered_messages': metadata['messages_number_1'] + 1}
    syslog_simulator_thread_2 = ThreadExecutor(syslog_simulator, {'parameters': syslog_simulator_parameters_2})
    syslog_simulator_thread_2.start()

    # Wait until all events have been processed
    waiting_time = ((metadata['messages_number_1'] + metadata['messages_number_2']) /
                    (metadata['maximum'] * metadata['timeframe'])) * metadata['timeframe'] + SYSLOG_SIMULATOR_START_TIME
    time.sleep(waiting_time)

    # Read the events log data
    events_data = file.read_file(ARCHIVES_LOG_PATH).split('\n')
    expected_num_events = metadata['messages_number_1'] + metadata['messages_number_2']

    # Check that all events have been recorded in the log file
    assert len(events_data) >= expected_num_events, \
        f"Not all expected events were found in the archives.log. Found={len(events_data)}, " \
        f"expected>={expected_num_events}"

    # Get the IDs of event messages
    event_ids = [int(re.search(fr"{metadata['message']} - (\d+)", event).group(1)) for event in events_data
                 if bool(re.match(fr".*{metadata['message']} - (\d+)", event))]

    # Check that the event message IDs are in order
    assert all(event_ids[i] <= event_ids[i+1] for i in range(len(event_ids) - 1)), 'Events have not been processed ' \
                                                                                   'in the expected order'

    # Wait until syslog simulator ends
    syslog_simulator_thread_1.join()
    syslog_simulator_thread_2.join()


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('configuration, metadata', zip(t5_configurations, t5_configuration_metadata), ids=t5_case_ids)
def test_event_processing_in_order_multi_thread(configuration, metadata, load_wazuh_basic_configuration,
                                                set_wazuh_configuration, configure_local_internal_options_function,
                                                truncate_event_logs, restart_wazuh_daemon_function):
    """
    description: Check that events are processed in order according to the position within the queue, and
        that events that are being received during the blocking phase are being added to the end of the queue when
        using multi-thread processing.

    test_phases:
        - setup:
            - Load Wazuh light configuration.
            - Apply ossec.conf configuration changes according to the configuration template and use case.
            - Apply custom settings in local_internal_options.conf.
            - Truncate wazuh event logs.
            - Restart wazuh-manager service to apply configuration changes.
        - test:
            - Send a batch of identified events.
            - Wait a few seconds, then send another batch of identified events. This is repeated n times.
            - Wait until all events are processed.
            - Read the event log (archives.log) and check that the events have been processed in the expected order.
        - tierdown:
            - Truncate wazuh event logs.
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
        - truncate_event_logs:
            type: fixture
            brief: Truncate wazuh event logs.
        - restart_wazuh_daemon_function:
            type: fixture
            brief: Restart the wazuh service.

    assertions:
        - Check that all expected events have been stored in the archives.log.
        - Check that all events have been generated in the archives.log according to the expected order.

    input_description:
        - The `configuration_event_processing_in_order_multi_thread` file provides the module configuration for this
          test.
        - The `cases_event_processing_in_order_multi_thread` file provides the test cases.
    """
    # Set syslog simulator parameters according to the use case data
    parameters = []
    syslog_simulator_threads = []
    syslog_simulator_parameters = {'address': metadata['address'], 'port': metadata['port'],
                                   'protocol': metadata['protocol'], 'eps': metadata['eps'],
                                   'messages_number': metadata['messages_number'], 'message': metadata['message_1']}
    # Create syslog simulator threads
    for index in range(metadata['num_batches']):
        parameters.append(deepcopy(syslog_simulator_parameters))
        parameters[index].update({'message': metadata[f"message_{index + 1}"]})
        syslog_simulator_threads.append(ThreadExecutor(syslog_simulator, {'parameters': parameters[index]}))

    # Start syslog simulator threads
    for thread in syslog_simulator_threads:
        thread.start()
        time.sleep(metadata['batch_sending_time'])

    # Wait until all events have been processed
    waiting_time_to_process_all_events = \
        ((metadata['messages_number'] * metadata['num_batches']) /
         (metadata['maximum'] * metadata['timeframe'])) * metadata['timeframe'] + SYSLOG_SIMULATOR_START_TIME

    waited_time_to_create_threads = metadata['batch_sending_time'] * metadata['num_batches']
    time.sleep(waiting_time_to_process_all_events - waited_time_to_create_threads)

    # Read the events log data
    events_data = file.read_file(ARCHIVES_LOG_PATH).split('\n')
    expected_num_events = metadata['batch_sending_time'] * metadata['num_batches']

    # Check that all events have been recorded in the log file
    assert len(events_data) >= expected_num_events, \
        f"Not all expected events were found in the archives.log. Found={len(events_data)}, " \
        f"expected>={expected_num_events}"

    # Get the IDs of event messages
    event_ids = [int(re.search(fr"{metadata['message_1']} - Group (\d+)", event).group(1)) for event in events_data
                 if bool(re.match(fr".*{metadata['message_1']} - Group (\d+)", event))]

    # Check that the event message IDs are in order
    assert all(event_ids[i] <= event_ids[i+1] for i in range(len(event_ids) - 1)), 'Events have not been processed ' \
                                                                                   'in the expected order'
    # Wait until all syslog simulator threads finish
    for thread in syslog_simulator_threads:
        thread.join()
