import os
from time import sleep
from datetime import datetime
import pytest

from wazuh_testing.tools.configuration import load_configuration_template, get_test_cases_data, \
get_simulate_agent_configuration
from wazuh_testing.modules.eps import event_monitor as evm
from wazuh_testing.tools.services import control_service


pytestmark = [pytest.mark.server]

# Reference paths
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, 'configuration_template')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases')
CONFIGURATIONS_SIMULATE_AGENT_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'data')

# Configuration and cases data
configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_eps.yaml')
configurations_simulate_agent_path = os.path.join(CONFIGURATIONS_SIMULATE_AGENT_PATH,
                                                  'configuration_simulate_agent.yaml')
t1_cases_path = os.path.join(TEST_CASES_PATH, 'cases_enabled.yaml')
t2_cases_path = os.path.join(TEST_CASES_PATH, 'cases_disabled.yaml')
t3_cases_path = os.path.join(TEST_CASES_PATH, 'cases_invalid_value.yaml')
t4_cases_path = os.path.join(TEST_CASES_PATH, 'cases_stop_process_events.yaml')
t5_cases_path = os.path.join(TEST_CASES_PATH, 'cases_start_queueing_events.yaml')
t6_cases_path = os.path.join(TEST_CASES_PATH, 'cases_start_dropping_events.yaml')
t7_cases_path = os.path.join(TEST_CASES_PATH, 'cases_process_old_events_instead_new_events.yaml')
t8_cases_path = os.path.join(TEST_CASES_PATH, 'cases_disabled_eps.yaml')

# Enabled test configurations (t1)
t1_configuration_parameters, t1_configuration_metadata, t1_case_ids = get_test_cases_data(t1_cases_path)
t1_configurations = load_configuration_template(configurations_path, t1_configuration_parameters,
                                                t1_configuration_metadata)

# Disabled test configurations (t2)
t2_configuration_parameters, t2_configuration_metadata, t2_case_ids = get_test_cases_data(t2_cases_path)
t2_configurations = load_configuration_template(configurations_path, t2_configuration_parameters,
                                                t2_configuration_metadata)

# Invalid value test configurations (t3)
t3_configuration_parameters, t3_configuration_metadata, t3_case_ids = get_test_cases_data(t3_cases_path)
t3_configurations = load_configuration_template(configurations_path, t3_configuration_parameters,
                                                t3_configuration_metadata)

# Stop processing events test configurations (t4)
t4_configuration_parameters, t4_configuration_metadata, t4_case_ids = get_test_cases_data(t4_cases_path)
t4_configurations = load_configuration_template(configurations_path, t4_configuration_parameters,
                                                t4_configuration_metadata)

# Start queueing events test configurations (t5)
t5_configuration_parameters, t5_configuration_metadata, t5_case_ids = get_test_cases_data(t5_cases_path)
t5_configurations = load_configuration_template(configurations_path, t5_configuration_parameters,
                                                t5_configuration_metadata)

# Start dropping events test configurations (t6)
t6_configuration_parameters, t6_configuration_metadata, t6_case_ids = get_test_cases_data(t6_cases_path)
t6_configurations = load_configuration_template(configurations_path, t6_configuration_parameters,
                                                t6_configuration_metadata)

# Process old events instead of new ones test configurations (t7)
t7_configuration_parameters, t7_configuration_metadata, t7_case_ids = get_test_cases_data(t7_cases_path)
t7_configurations = load_configuration_template(configurations_path, t7_configuration_parameters,
                                                t7_configuration_metadata)

# Disabled EPS test configurations (t8)
t8_configuration_parameters, t8_configuration_metadata, t8_case_ids = get_test_cases_data(t8_cases_path)
t8_configurations = load_configuration_template(configurations_path, t8_configuration_parameters,
                                                t8_configuration_metadata)

# wazuh-analysisd.state file default update configuration
analysisd_state_interval_default = '5'
percentage_of_process_msgs = 0.75

# Get simulate agent configurations (t4)
params_stop_processing_events = get_simulate_agent_configuration(configurations_simulate_agent_path)
maximun_eps = [metadata['maximun'] for metadata in t4_configuration_metadata]
timeframe_eps_t4 = [metadata['timeframe'] for metadata in t4_configuration_metadata]
events_per_sec = maximun_eps[0] * 500
params_stop_processing_events.update({'events_per_sec': events_per_sec})

# Get simulate agent configurations (t5)
params_start_queuing_events_when_limit_reached = get_simulate_agent_configuration(configurations_simulate_agent_path)
maximun_eps = [metadata['maximun'] for metadata in t5_configuration_metadata]
timeframe_eps_t5 = [metadata['timeframe'] for metadata in t5_configuration_metadata]
events_per_sec = maximun_eps[0] * 10
params_start_queuing_events_when_limit_reached.update({'events_per_sec': events_per_sec})

# Get simulate agent configurations (t6)
params_start_dropping_events_when_queue_full = get_simulate_agent_configuration(configurations_simulate_agent_path)
maximun_eps = [metadata['maximun'] for metadata in t6_configuration_metadata]
timeframe_eps_t6 = [metadata['timeframe'] for metadata in t6_configuration_metadata]
events_per_sec = maximun_eps[0] * 1000
params_start_dropping_events_when_queue_full.update({'events_per_sec': events_per_sec})

# Get simulate agent configurations (t7)
params_process_old_events_instead_new = get_simulate_agent_configuration(configurations_simulate_agent_path)
maximun_eps = [metadata['maximun'] for metadata in t7_configuration_metadata]
timeframe_eps_t7 = [metadata['timeframe'] for metadata in t7_configuration_metadata]
events_per_sec = maximun_eps[0] * 500
params_process_old_events_instead_new.update({'events_per_sec': events_per_sec})

# Get simulate agent configurations (t8)
params_disabled_eps = get_simulate_agent_configuration(configurations_simulate_agent_path)
timeframe_eps_t8 = [metadata['timeframe'] for metadata in t8_configuration_metadata]
events_per_sec = 10000
params_disabled_eps.update({'events_per_sec': events_per_sec})


@pytest.mark.parametrize('configuration, metadata', zip(t1_configurations, t1_configuration_metadata), ids=t1_case_ids)
@pytest.mark.parametrize('configure_local_internal_options_eps', [analysisd_state_interval_default], indirect=True)
def test_enabled(configuration, metadata, set_wazuh_configuration_eps,
                 truncate_monitored_files, restart_wazuh_daemon_function):
    '''
    description: Check that limits EPS is started when `maximum` is set to a value greater than 0 lower and than 100000,
                 and `timeframe` is set to a value greater than 0 and lower than 3600.

    test_phases:
        - Set a custom Wazuh configuration.
        - Truncate logs files.
        - Restart wazuh-daemons.
        - Check in the log that the EPS limits is enabled.

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
        - truncate_monitored_files:
            type: fixture
            brief: Truncate all the log files and json alerts files before and after the test execution.
        - restart_wazuh_daemon_function:
            type: fixture
            brief: Restart all the wazuh daemons.

    assertions:
        - Verify that when the `maximum` value is set to a values greater than 0 and lower than 100000 and, `timeframe`
          value is set to a value greater than 0 and lower than 3600, the module EPS limits is running.

    input_description:
        - The `cases_enabled.yaml` file provides the module configuration for this test.

    expected_output:
        - r'(.*)wazuh-analysisd: INFO: EPS limit enabled, EPS: (.*), timeframe: (.*)'
    '''
    evm.check_eps_enabled(metadata['maximun'], metadata['timeframe'])


@pytest.mark.parametrize('configuration, metadata', zip(t2_configurations, t2_configuration_metadata), ids=t2_case_ids)
@pytest.mark.parametrize('configure_local_internal_options_eps', [analysisd_state_interval_default], indirect=True)
def test_disabled(configuration, metadata, set_wazuh_configuration_eps,
                 truncate_monitored_files, restart_wazuh_daemon_function):
    '''
    description: Check that limits EPS is not started when `maximum` is set to a value equal to 0, or with an empty
                 value, and `timeframe` is set to a value greater than 0 and lower than 3600.

    test_phases:
        - Set a custom Wazuh configuration.
        - Truncate logs files.
        - Restart wazuh-daemons.
        - Check in the log that the EPS limits is disabled.

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
        - truncate_monitored_files:
            type: fixture
            brief: Truncate all the log files and json alerts files before and after the test execution.
        - restart_wazuh_daemon_function:
            type: fixture
            brief: Restart all the wazuh daemons.

    assertions:
        - Verify that when the `maximum` value is set to 0 or with an empty value and, `timeframe` value is set to a
          value greater than 0 and lower than 3600, the module EPS limits is not running.

    input_description:
        - The `cases_disabled.yaml` file provides the module configuration for this test.

    expected_output:
        - r'(.*)wazuh-analysisd: INFO: EPS limit disabled'
    '''
    evm.check_eps_disabled()


@pytest.mark.parametrize('configuration, metadata', zip(t3_configurations, t3_configuration_metadata), ids=t3_case_ids)
@pytest.mark.parametrize('configure_local_internal_options_eps', [analysisd_state_interval_default], indirect=True)
def test_invalid_value(configuration, metadata, set_wazuh_configuration_eps,
                       truncate_monitored_files, restart_wazuh_daemon_after_finishing):
    '''
    description: Check that wazuh manager is not started when an invalid value is set to `maximum` and/or `timeframe`.

    test_phases:
        - Set a custom Wazuh configuration.
        - Truncate logs files.
        - Restart wazuh-daemons.
        - Check that wazuh manager does not start.

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
        - truncate_monitored_files:
            type: fixture
            brief: Truncate all the log files and json alerts files before and after the test execution.
        - restart_wazuh_daemon_after_finishing:
            type: fixture
            brief: Restart wazuh modules after finishing the test module.

    assertions:
        - The error message appears when the `maximum` and/or `timeframe` values have invalid values.

    input_description:
        - The `cases_invalid_value.yaml` file provides the module configuration for this test.

    expected_output:
        - r'.*: Configuration error at.*'
    '''
    try:
        control_service('restart')
    except ValueError:
        evm.check_configuration_error()


@pytest.mark.parametrize('configuration, metadata', zip(t4_configurations, t4_configuration_metadata), ids=t4_case_ids)
@pytest.mark.parametrize('configure_local_internal_options_eps', [timeframe_eps_t4], indirect=True)
@pytest.mark.parametrize('simulate_agent', [params_stop_processing_events], indirect=True)
def test_stops_processing_events(configuration, metadata, set_wazuh_configuration_eps, truncate_monitored_files,
                                 restart_wazuh_daemon_function, simulate_agent):
    '''
    description: Check that the `events_processed` value in the `/var/ossec/var/run/wazuh-analysisd.state` file must
                 be lower or equal than `maximun` * `timeframe`

    test_phases:
        - Set a custom Wazuh configuration.
        - Truncate logs files.
        - Restart wazuh-daemons.
        - Execute agent simulated script.

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
        - truncate_monitored_files:
            type: fixture
            brief: Truncate all the log files and json alerts files before and after the test execution.
        - restart_wazuh_daemon_function:
            type: fixture
            brief: Restart all the wazuh daemons.
        - simulate_agent:
            type: fixture
            brief: Execute a script that simulate agent and send `logcolector` logs to the manager.

    assertions:
        - The `events_processed` value in the `/var/ossec/var/run/wazuh-analysisd.state` file must be lower or equal
          than `maximun` * `timeframe` and greater than a percentage of `maximun` * `timeframe` to confirm that
          `events_processed` is not null.

    input_description:
        - The `cases_stop_process_events.yaml` file provides the module configuration for this test.
    '''
    sleep(metadata['timeframe'] / 2)
    events_processed = evm.get_analysisd_state('events_processed')

    # Check that processed events reach the EPS limit
    assert events_processed <= float(metadata['maximun'] * metadata['timeframe']) and \
           events_processed >= float(metadata['maximun'] * metadata['timeframe']) * percentage_of_process_msgs, \
           'events_processed must be lower or equal to maximun * timeframe'


@pytest.mark.parametrize('configuration, metadata', zip(t5_configurations, t5_configuration_metadata), ids=t5_case_ids)
@pytest.mark.parametrize('configure_local_internal_options_eps', [timeframe_eps_t5], indirect=True)
@pytest.mark.parametrize('simulate_agent', [params_start_queuing_events_when_limit_reached], indirect=True)
def test_start_queuing_events_when_limit_reached(configuration, metadata, set_wazuh_configuration_eps,
                                                  truncate_monitored_files, restart_wazuh_daemon_function,
                                                  simulate_agent):
    '''
    description: Check that the `events_processed` value in the `/var/ossec/var/run/wazuh-analysisd.state` file must
                 be lower or equal than `maximun` * `timeframe` and, the `events_received` value must be greater than
                 `events_processed` and, the `events_dropped` value equal to 0 and finaly, `event_queue_usage` is lower
                 than 1.0.

    test_phases:
        - Set a custom Wazuh configuration.
        - Truncate logs files.
        - Restart wazuh-daemons.
        - Execute agent simulated script.

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
        - truncate_monitored_files:
            type: fixture
            brief: Truncate all the log files and json alerts files before and after the test execution.
        - restart_wazuh_daemon_function:
            type: fixture
            brief: Restart all the wazuh daemons.
        - simulate_agent:
            type: fixture
            brief: Execute a script that simulate agent and send `logcolector` logs to the manager.

    assertions:
        - The `events_processed` value in the `/var/ossec/var/run/wazuh-analysisd.state` file must be lower or equal
          than `maximun` * `timeframe` and greater than a percentage of `maximun` * `timeframe` to confirm that
          `events_processed` is not null. The `events_received` value must be greater than `events_processed` and,
          the `events_dropped` value equal to 0 and finaly, `event_queue_usage` is lower than 1.0.

    input_description:
        - The `cases_start_queueing_events.yaml` file provides the module configuration for this test.
    '''
    sleep(metadata['timeframe'] / 2)
    events_processed = evm.get_analysisd_state('events_processed')
    events_received = evm.get_analysisd_state('events_received')
    events_dropped = evm.get_analysisd_state('events_dropped')
    event_queue_usage = evm.get_analysisd_state('event_queue_usage')

    # Check that processed events reach the EPS limit
    assert events_processed <= float(metadata['maximun'] * metadata['timeframe']) and \
           events_processed >= float(metadata['maximun'] * metadata['timeframe']) * percentage_of_process_msgs, \
           'events_processed must be lower or equal to maximun * timeframe'

    # Check that events continue receiving although the EPS limit was reached
    assert events_received > events_processed, 'events_received must be bigger than events_processed'

    # Check that there are not events dropped and the queue usage is less than 1.0 (100%).
    # This means the queue is not full
    assert events_dropped == 0 and event_queue_usage < 1.0, 'events_dropped must be 0 and event_queue_usage less' \
           'than 1.0'


@pytest.mark.parametrize('configuration, metadata', zip(t6_configurations, t6_configuration_metadata), ids=t6_case_ids)
@pytest.mark.parametrize('configure_local_internal_options_eps', [timeframe_eps_t6], indirect=True)
@pytest.mark.parametrize('simulate_agent', [params_start_dropping_events_when_queue_full], indirect=True)
def test_start_dropping_events_when_queue_full(configuration, metadata, set_wazuh_configuration_eps,
                                               truncate_monitored_files, restart_wazuh_daemon_function,
                                               simulate_agent):
    '''
    description: Check that the `events_dropped` value in the `/var/ossec/var/run/wazuh-analysisd.state` file must
                 be greater than 1 and, `event_queue_usage` is equal to 1
                 than 1.0.

    test_phases:
        - Set a custom Wazuh configuration.
        - Truncate logs files.
        - Restart wazuh-daemons.
        - Execute agent simulated script.

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
        - truncate_monitored_files:
            type: fixture
            brief: Truncate all the log files and json alerts files before and after the test execution.
        - restart_wazuh_daemon_function:
            type: fixture
            brief: Restart all the wazuh daemons.
        - simulate_agent:
            type: fixture
            brief: Execute a script that simulate agent and send `logcolector` logs to the manager.

    assertions:
        - The `events_processed` value in the `/var/ossec/var/run/wazuh-analysisd.state` file must be lower or equal
          than `maximun` * `timeframe` and greater than a percentage of `maximun` * `timeframe` to confirm that
          `events_processed` is not null. The `events_received` value must be greater than `events_processed` and,
          the `events_dropped` value greater than 0 and finaly, `event_queue_usage` is equal to 1.0.

    input_description:
        - The `cases_start_queueing_events.yaml` file provides the module configuration for this test.
    '''
    sleep(metadata['timeframe'] / 2)
    events_processed = evm.get_analysisd_state('events_processed')
    events_received = evm.get_analysisd_state('events_received')
    events_dropped = evm.get_analysisd_state('events_dropped')
    event_queue_usage = evm.get_analysisd_state('event_queue_usage')

    # Check that processed events reach the EPS limit
    assert events_processed <= float(metadata['maximun'] * metadata['timeframe']) and \
           events_processed >= float(metadata['maximun'] * metadata['timeframe']) * percentage_of_process_msgs, \
           'events_processed must be lower or equal to maximun * timeframe'

    # Check that events continue receiving although the EPS limit was reached
    assert events_received > events_processed, 'events_received must be bigger than events_processed'

    # Check that there is no event dropped and the queue usage is less than 1.0 (100%). This means the queue is not full
    assert events_dropped > 0 and event_queue_usage == 1.0, 'events_dropped must be bigger than 0 and' \
           'event_queue_usage must be 1.0'


@pytest.mark.parametrize('configuration, metadata', zip(t7_configurations, t7_configuration_metadata), ids=t7_case_ids)
@pytest.mark.parametrize('configure_local_internal_options_eps', [timeframe_eps_t7], indirect=True)
@pytest.mark.parametrize('simulate_agent', [params_process_old_events_instead_new], indirect=True)
def test_process_old_events_instead_new_events(configuration, metadata, set_wazuh_configuration_eps,
                                               configure_internal_options_eps, truncate_monitored_files,
                                               delete_alerts_folder, restart_wazuh_daemon_function, simulate_agent):
    '''
    description: Check that `wazuh-analysisd` processes queued events first instead of new events when the moving
                 average frees up some space. To do this, read the alerts.log file and find the numerated alerts
                 messages and gets the timestamp. The oldest message must have lower timestamp

    test_phases:
        - Set a custom Wazuh configuration.
        - Truncate logs files.
        - Restart wazuh-daemons.
        - Execute agent simulated script.

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
        - The `cases_process_old_events_instead_new_events.yaml` file provides the module configuration for this test.
    '''
    # Set logcollector message that the agent sents
    logcollector_message = 'Invalid user random_user from 172.17.1.1 port 56550:Message number:'
    # Set the alerts start message
    start_alert_msg = '** Alert '
    # Initial timestamp to compare
    timestamp_bkp = datetime.fromtimestamp(float(0.0)).strftime('%Y-%m-%d %H:%M:%S')
    # Factor to iterate the alerts.log file to reduce the test execution time
    time_events_processed = 5

    # Ensure that the test start in the middle of a timeframe
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
        raise Exception('Not enough messages were sent it. Please increase the `events_per_sec` for ' \
                        'this test.')


@pytest.mark.parametrize('configuration, metadata', zip(t8_configurations, t8_configuration_metadata), ids=t8_case_ids)
@pytest.mark.parametrize('configure_local_internal_options_eps', [timeframe_eps_t8], indirect=True)
@pytest.mark.parametrize('simulate_agent', [params_disabled_eps], indirect=True)
def test_disabled_eps(configuration, metadata, set_wazuh_configuration_eps,
                      truncate_monitored_files, restart_wazuh_daemon_function, simulate_agent):

    sleep(metadata['timeframe'] / 2)
    evm.check_eps_disabled()
    events_processed = evm.get_analysisd_state('events_processed')
    events_received = evm.get_analysisd_state('events_received')

    assert events_processed >= events_received * percentage_of_process_msgs or \
           events_processed <= events_received * percentage_of_process_msgs, 'The events_processed value is '\
                                                                             'similar to events_received'
