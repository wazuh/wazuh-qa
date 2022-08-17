import os
from time import sleep
from datetime import datetime
import pytest

from wazuh_testing.tools.configuration import load_configuration_template, get_test_cases_data, \
get_simulate_agent_configuration
from wazuh_testing.modules.eps import event_monitor as evm
from wazuh_testing.modules.eps import PERCENTAGE_PROCESS_MSGS, QUEUE_SIZE


pytestmark = [pytest.mark.server]

# Reference paths
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, 'configuration_template')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases')

# Configuration and cases data
configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_stop_processing_events.yaml')
configurations_simulate_agent_path = os.path.join(TEST_DATA_PATH,
                                                  'configuration_simulate_agent.yaml')
t1_cases_path = os.path.join(TEST_CASES_PATH, 'cases_stop_process_events.yaml')

# Stop processing events test configurations (t1)
t1_configuration_parameters, t1_configuration_metadata, t1_case_ids = get_test_cases_data(t1_cases_path)
t1_configurations = load_configuration_template(configurations_path, t1_configuration_parameters,
                                                t1_configuration_metadata)

# Get simulate agent configurations (t1)
params_stop_processing_events = get_simulate_agent_configuration(configurations_simulate_agent_path)
maximum_eps = [metadata['maximum'] for metadata in t1_configuration_metadata]
timeframe_eps_t1 = [metadata['timeframe'] for metadata in t1_configuration_metadata]
total_msg = maximum_eps[0] * timeframe_eps_t1[0] * 3
if total_msg > QUEUE_SIZE:
    total_msg = QUEUE_SIZE - 1
params_stop_processing_events.update({'total_msg': total_msg})


@pytest.mark.parametrize('configuration, metadata', zip(t1_configurations, t1_configuration_metadata), ids=t1_case_ids)
@pytest.mark.parametrize('configure_local_internal_options_eps', [timeframe_eps_t1], indirect=True)
@pytest.mark.parametrize('simulate_agent', [params_stop_processing_events], indirect=True)
def test_stops_processing_events(configuration, metadata, set_wazuh_configuration_eps, truncate_monitored_files,
                                 restart_wazuh_daemon_function, simulate_agent):
    '''
    description: Check that the `events_processed` value in the `/var/ossec/var/run/wazuh-analysisd.state` file must
                 be lower or equal than `maximum` * `timeframe`

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
          than `maximum` * `timeframe` and greater than a percentage of `maximum` * `timeframe` to confirm that
          `events_processed` is not null.

    input_description:
        - The `cases_stop_process_events.yaml` file provides the module configuration for this test.
    '''
    # Wait 'timeframe' / 2 second to read the wazuh-analysisd.state to ensure that has corrects values
    sleep(metadata['timeframe'] / 2)
    events_processed = evm.get_analysisd_state('events_processed')

    # Check that processed events reach the EPS limit
    assert events_processed <= float(metadata['maximum'] * metadata['timeframe']) and \
           events_processed >= float(metadata['maximum'] * metadata['timeframe']) * PERCENTAGE_PROCESS_MSGS, \
           'events_processed must be lower or equal to maximum * timeframe'
