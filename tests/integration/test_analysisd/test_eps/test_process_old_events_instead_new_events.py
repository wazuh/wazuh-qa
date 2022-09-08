import os
from time import sleep
from datetime import datetime
import pytest

from wazuh_testing.tools.configuration import load_configuration_template, get_test_cases_data, \
                                              get_syslog_simulator_configuration
from wazuh_testing.modules.eps import event_monitor as evm
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.run_simulator import syslog_simulator
from wazuh_testing.tools import ALERT_FILE_PATH


pytestmark = [pytest.mark.server]

# Global variables
PATTERN_A = 'AAAA'
PATTERN_B = 'BBBB'
PATTERN_C = 'CCCC'
SYSLOG_CUSTOM_MESSAGE = f"Login failed: admin, test {PATTERN_A}, Message number:"

# Reference paths
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, 'configuration_template')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases')

# Configuration and cases data
configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_process_old_events.yaml')
configurations_syslog_simulator_path = os.path.join(TEST_DATA_PATH, 'configuration_syslog_simulator.yaml')
t1_cases_path = os.path.join(TEST_CASES_PATH, 'cases_process_old_events_one_thread.yaml')
t2_cases_path = os.path.join(TEST_CASES_PATH, 'cases_process_old_events_multi_thread.yaml')

# Process old events instead of new ones test configurations multi thread (t1)
t1_configuration_parameters, t1_configuration_metadata, t1_case_ids = get_test_cases_data(t1_cases_path)
t1_configurations = load_configuration_template(configurations_path, t1_configuration_parameters,
                                                t1_configuration_metadata)

# Process old events instead of new ones test configurations one thread (t2)
t2_configuration_parameters, t2_configuration_metadata, t2_case_ids = get_test_cases_data(t2_cases_path)
t2_configurations = load_configuration_template(configurations_path, t2_configuration_parameters,
                                                t2_configuration_metadata)

# Get simulate agent configurations (t1)
params_process_old_events_one_thread = get_syslog_simulator_configuration(configurations_syslog_simulator_path)
local_internal_configuration_t1 = [
    {'wazuh_modules.debug': '2', 'monitord.rotate_log': '0', 'analysisd.state_interval': metadata['timeframe']}
    for metadata in t1_configuration_metadata
]

num_messages = 150
params_process_old_events_one_thread.update({'num_messages': num_messages})
params_process_old_events_one_thread.update({'message': f"\"{SYSLOG_CUSTOM_MESSAGE}\""})
params_process_old_events_one_thread.update({'interval_burst_time': 0})
params_process_old_events_one_thread.update({'messages_per_burst': 0})

# Get syslog simulator configurations (t2)
params_process_old_events_multithread = get_syslog_simulator_configuration(configurations_syslog_simulator_path)
local_internal_configuration_t2 = [
    {'wazuh_modules.debug': '2', 'monitord.rotate_log': '0', 'analysisd.state_interval': metadata['timeframe']}
    for metadata in t2_configuration_metadata
]


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('configuration, metadata', zip(t1_configurations, t1_configuration_metadata), ids=t1_case_ids)
@pytest.mark.parametrize('configure_local_internal_options_module', local_internal_configuration_t1, indirect=True)
@pytest.mark.parametrize('syslog_simulator_function', [params_process_old_events_one_thread], indirect=True)
def test_process_old_events_one_thread(configuration, metadata, load_wazuh_basic_configuration,
                                       configure_local_internal_options_module, configure_wazuh_one_thread,
                                       truncate_monitored_files, restart_wazuh_daemon_function,
                                       syslog_simulator_function):
    '''
    description: Check that `wazuh-analysisd` processes queued events first instead of new events. To do this, it is
                 read the alerts.json file and it is stored the messages timestamp. The oldest message must have the
                 lowest timestamp. First it must set the `internal_options.conf` file to work with one thread,
                 otherwise the message are not in the increasing order.

    test_phases:
        - Set a custom Wazuh configuration.
        - Truncate logs files.
        - Restart wazuh-daemons.
        - Execute syslog simulator script.
        - Check alerts.json file.

    wazuh_min_version: 4.4.0

    tier: 0

    parameters:
        - configuration:
            type: dict
            brief: Wazuh configuration data. Needed for set_wazuh_configuration fixture.
        - metadata:
            type: dict
            brief: Wazuh configuration metadata.
        - load_wazuh_basic_configuration
            type: fixture
            brief: Load a basic configuration to the manager.
        - set_wazuh_configuration_analysisd:
            type: fixture
            brief: Set the wazuh configuration according to the configuration data.
        - configure_wazuh_one_thread:
            type: fixture
            brief: Set the wazuh internal option configuration according to the configuration data.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate all the log files and json alerts files before and after the test execution.
        - restart_wazuh_daemon_function:
            type: fixture
            brief: Restart all the wazuh daemons.
        - syslog_simulator_function:
            type: fixture
            brief: Execute a script that send syslog messages to the manager.

    assertions:
        - The timestamp of the oldest numerated messages have to be lower than the previous messages.
        - The message must be in increase order.

    input_description:
        - The `cases_process_old_events_one_thread.yaml` file provides the module configuration for this test.
    '''
    # Initial timestamp to compare
    timestamp_bkp = datetime.strptime('0001-01-01T00:00:00.000+0000', '%Y-%m-%dT%H:%M:%S.%f+0000')
    regex = fr".*\"timestamp\":\"([^\"]*)\".*Login failed: admin, test AAAA, Message number: (\d+).*"
    file_monitor = FileMonitor(ALERT_FILE_PATH)
    timestamp_list = evm.get_messages_info(file_monitor, regex, num_messages)
    # Check that the timestamp of the message in the alerts.json is lower than the next one, and messages are stored
    # secuentially
    index = 0
    for element in timestamp_list:
        # Get the timestamp of the log
        timestamp = datetime.strptime(element[0], '%Y-%m-%dT%H:%M:%S.%f+0000')
        message_index = int(element[1])
        # Check that the timestamp of the next message is lower than the previous one
        assert timestamp >= timestamp_bkp, f"The timestamp of the previous message {timestamp_bkp} has to be "\
                                           f"lower than the follow one {timestamp}"
        assert message_index == index, "The messages were not stored in increasing orded. Message index" \
                                       f"stored {message_index} shoud be in possition {index}"
        # Store the timestamp to be compared with the next one
        timestamp_bkp = timestamp
        # Increase index to check the next message
        index += 1


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('configuration, metadata', zip(t2_configurations, t2_configuration_metadata), ids=t2_case_ids)
@pytest.mark.parametrize('configure_local_internal_options_module', local_internal_configuration_t2, indirect=True)
def test_process_old_events_multi_thread(configuration, metadata, load_wazuh_basic_configuration,
                                         set_wazuh_configuration, configure_local_internal_options_module,
                                         truncate_monitored_files, restart_wazuh_daemon_function):
    '''
    description: Check that `wazuh-analysisd` processes queued events first instead of new events. To do this, it is
                 sent three groups of messages with different content per groups (A, B and C). Then, it checks that
                 each group of messages received belong to the rescpective timeframe in the correct order, first group
                 A, the B an last C group.

    test_phases:
        - Set a custom Wazuh configuration.
        - Truncate logs files.
        - Restart wazuh-daemons.
        - Check alerts.json file.

    wazuh_min_version: 4.4.0

    tier: 0

    parameters:
        - configuration:
            type: dict
            brief: Wazuh configuration data. Needed for set_wazuh_configuration fixture.
        - metadata:
            type: dict
            brief: Wazuh configuration metadata.
        - load_wazuh_basic_configuration
            type: fixture
            brief: Load a basic configuration to the manager.
        - set_wazuh_configuration_analysisd:
            type: fixture
            brief: Set the wazuh configuration according to the configuration data.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate all the log files and json alerts files before and after the test execution.
        - restart_wazuh_daemon_function:
            type: fixture
            brief: Restart all the wazuh daemons.

    assertions:
        - The messages content type must have the same order that it has been sent.

    input_description:
        - The `cases_process_old_events_multi_thread.yaml` file provides the module configuration for this test.
    '''
    patern_list = [PATTERN_A, PATTERN_B, PATTERN_C]
    total_msg_list = []
    regex = fr".*Login failed: admin, test (\w+), Message number: (\d+).*"
    messages_sent = int(params_process_old_events_multithread['num_messages'])

    # Send custom messages type PATTERN_A
    custom_message = SYSLOG_CUSTOM_MESSAGE
    params_process_old_events_multithread.update({'message': f"\"{custom_message}\""})
    syslog_simulator(params_process_old_events_multithread)
    sleep(metadata['timeframe'] / 2)
    # Create a filemonitor
    file_monitor = FileMonitor(ALERT_FILE_PATH)
    # Get total PATTERN_A messages
    total_msg_list.append(evm.get_messages_info(file_monitor, regex, messages_sent))

    # Send custom messages type PATTERN_B
    custom_message = custom_message.replace(PATTERN_A, PATTERN_B)
    params_process_old_events_multithread.update({'message': f"\"{custom_message}\""})
    syslog_simulator(params_process_old_events_multithread)
    sleep(metadata['timeframe'] / 2)
    # Get total PATTERN_B messages
    total_msg_list.append(evm.get_messages_info(file_monitor, regex, messages_sent))

    # Send custom messages type PATTERN_C
    custom_message = custom_message.replace(PATTERN_B, PATTERN_C)
    params_process_old_events_multithread.update({'message': f"\"{custom_message}\""})
    syslog_simulator(params_process_old_events_multithread)
    sleep(metadata['timeframe'] / 2)
    # Get total PATTERN_C messages
    total_msg_list.append(evm.get_messages_info(file_monitor, regex, messages_sent))
    # Check messages order pattern
    index_patern = 0
    for element in total_msg_list:
        for index in range(len(element)):
            assert element[index][0] == patern_list[index_patern]
        index_patern += 1
