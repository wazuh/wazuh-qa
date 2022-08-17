import os
from time import sleep
from datetime import datetime
import pytest

from wazuh_testing.tools.configuration import load_configuration_template, get_test_cases_data, \
get_simulate_agent_configuration
from wazuh_testing.modules.eps import event_monitor as evm


pytestmark = [pytest.mark.server]

# Reference paths
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, 'configuration_template')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases')

# Configuration and cases data
configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_process_old_events_instead_new_events.yaml')
configurations_simulate_agent_path = os.path.join(TEST_DATA_PATH,
                                                  'configuration_simulate_agent.yaml')
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
params_process_old_events_one_thread = get_simulate_agent_configuration(configurations_simulate_agent_path)
timeframe_eps_t1 = [metadata['timeframe'] for metadata in t1_configuration_metadata]
total_msg = 10000 # of 1Kb message of 16384 Kb of queue size
params_process_old_events_one_thread.update({'total_msg': total_msg})

# Get simulate agent configurations (t2)
params_process_old_events_multithread = get_simulate_agent_configuration(configurations_simulate_agent_path)
maximun_eps_t2 = [metadata['maximun'] for metadata in t2_configuration_metadata]
timeframe_eps_t2 = [metadata['timeframe'] for metadata in t2_configuration_metadata]
# It is sent `width_frame` time frame width to reduce test time execution
frame_width = 3
total_msg = maximun_eps_t2[0] * timeframe_eps_t2[0] * frame_width
params_process_old_events_multithread.update({'total_msg': total_msg})

@pytest.mark.parametrize('configuration, metadata', zip(t1_configurations, t1_configuration_metadata), ids=t1_case_ids)
@pytest.mark.parametrize('configure_local_internal_options_eps', [timeframe_eps_t1], indirect=True)
@pytest.mark.parametrize('simulate_agent', [params_process_old_events_one_thread], indirect=True)
def test_process_old_events_one_thread(configuration, metadata, set_wazuh_configuration_eps,
                                       configure_internal_options_eps, truncate_monitored_files,
                                       delete_alerts_folder, restart_wazuh_daemon_function, simulate_agent):
    '''
    description: Check that `wazuh-analysisd` processes queued events first instead of new events when the moving
                 average frees up some space. To do this, read the alerts.log file and find the numerated alerts
                 messages and gets the timestamp. The oldest message must have lower timestamp. To do so, first it must
                 set the `internal_options.conf` file to work with one thread, otherwise the message are not in the
                 increasing order.

    test_phases:
        - Set a custom Wazuh configuration.
        - Truncate logs files.
        - Restart wazuh-daemons.
        - Execute agent simulated script.
        - Check alerts.log file.

    wazuh_min_version: 4.4.0

    tier: 0

    parameters:
        - configuration:
            type: dict
            brief: Wazuh configuration data. Needed for set_wazuh_configuration fixture.
        - metadata:
            type: dict
            brief: Wazuh configuration metadata.
        - set_wazuh_configuration_eps:
            type: fixture
            brief: Set the wazuh configuration according to the configuration data.
        - configure_internal_options_eps:
            type: fixture
            brief: Set the wazuh internal option configuration according to the configuration data.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate all the log files and json alerts files before and after the test execution.
        - delete_alerts_folder:
            type: fixture
            brief: Delete all the content od the /var/log/alerts folder.
        - restart_wazuh_daemon_function:
            type: fixture
            brief: Restart all the wazuh daemons.
        - simulate_agent:
            type: fixture
            brief: Execute a script that simulate agent and send `logcolector` logs to the manager.

    assertions:
        - The timestamp of the oldest numerated messages have to be lower than he new messages.

    input_description:
        - The `cases_process_old_events_one_thread.yaml` file provides the module configuration for this test.
    '''
    # Set logcollector message that the agent sents
    logcollector_message = 'Invalid user random_user from 172.17.1.1 port 56550:Message number:'
    # Set the alerts start message
    start_alert_msg = '** Alert '
    # Initial timestamp to compare
    timestamp_bkp = datetime.fromtimestamp(float(0.0)).strftime('%Y-%m-%d %H:%M:%S')
    # Factor to iterate the alerts.log file to reduce the test execution time
    time_events_processed = 5

    # Wait 'timeframe' / 2 second to read the wazuh-analysisd.state to ensure that has corrects values
    sleep(metadata['timeframe'] / 2)
    events_processed = int(evm.get_analysisd_state('events_processed'))
    events_received = int(evm.get_analysisd_state('events_received'))

    # Check that the timestamp of the message in the alerts.log is lower than the next one
    # In order to reduce the test time execution, It will check {time_events_processed} consecutive timeframe
    # by checking events_processed * time_events_processed
    if(events_processed * time_events_processed <= events_received):
        for index in range((events_processed * time_events_processed) - 1):
            # Get the timestamp of the log
            timestamp = evm.get_alert_timestamp(start_alert_msg, f"{logcollector_message} {index}")
            # Check that the timestamp of the first message y lower than the previous one
            assert timestamp >= timestamp_bkp, 'The timestamp of the previous message has to be lower than the '\
                                               'next one'
            # Store the timestamp to be compared with the next one
            timestamp_bkp = timestamp
    else:
        raise Exception('Not enough messages were sent. Please increase the `total_msg` for ' \
                        'this test.')


@pytest.mark.parametrize('configuration, metadata', zip(t2_configurations, t2_configuration_metadata), ids=t2_case_ids)
@pytest.mark.parametrize('configure_local_internal_options_eps', [timeframe_eps_t2], indirect=True)
@pytest.mark.parametrize('simulate_agent', [params_process_old_events_multithread], indirect=True)
def test_process_old_events_multi_thread(configuration, metadata, set_wazuh_configuration_eps,
                                               truncate_monitored_files, delete_alerts_folder,
                                               restart_wazuh_daemon_function, simulate_agent):
    '''
    description: Check that `wazuh-analysisd` processes queued events first instead of new events when the moving
                 average frees up some space. To do this, read the alerts.log file and find the numerated alerts
                 messages with the FileMonitor tool. To do so, it iterates the `n` frames of `maximun` * `timeframe` and
                 checks if the message number belongs to the respective frame.

    test_phases:
        - Set a custom Wazuh configuration.
        - Truncate logs files.
        - Restart wazuh-daemons.
        - Execute agent simulated script.
        - Check alerts.log file.

    wazuh_min_version: 4.4.0

    tier: 0

    parameters:
        - configuration:
            type: dict
            brief: Wazuh configuration data. Needed for set_wazuh_configuration fixture.
        - metadata:
            type: dict
            brief: Wazuh configuration metadata.
        - set_wazuh_configuration_eps:
            type: fixture
            brief: Set the wazuh configuration according to the configuration data.
        - configure_internal_options_eps:
            type: fixture
            brief: Set the wazuh internal option configuration according to the configuration data.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate all the log files and json alerts files before and after the test execution.
        - delete_alerts_folder:
            type: fixture
            brief: Delete all the content od the /var/log/alerts folder.
        - restart_wazuh_daemon_function:
            type: fixture
            brief: Restart all the wazuh daemons.
        - simulate_agent:
            type: fixture
            brief: Execute a script that simulate agent and send `logcolector` logs to the manager.

    assertions:
        - The timestamp of the oldest numerated messages have to be lower than he new messages.

    input_description:
        - The `cases_process_old_events_multi_thread.yaml` file provides the module configuration for this test.
    '''
    # Set logcollector message that the agent sents
    logcollector_message = 'Invalid user random_user from 172.17.1.1 port 56550:Message number:'
    # Wait 'timeframe' / 2 second to read the wazuh-analysisd.state to ensure that has corrects values
    sleep(metadata['timeframe'] / 2)
    events_received = evm.get_analysisd_state('events_received')
    index = 0
    frame = metadata['timeframe'] * metadata['maximun']
    # Iterate over each frame to find the respective numerated message belongs to the frame
    while (index + 1) * frame <= events_received:
        start_index = index * frame
        end_index = (index + 1) * frame
        # Iterate over the frame to find the respective numerated message
        for msg_number in range(start_index, end_index):
            evm.get_msg_with_number(fr".*{logcollector_message} {msg_number}")
        index += 1
