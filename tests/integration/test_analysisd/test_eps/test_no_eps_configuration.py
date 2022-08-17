import os
from time import sleep
import pytest

from wazuh_testing.tools.configuration import load_configuration_template, get_test_cases_data, \
get_simulate_agent_configuration
from wazuh_testing.modules.eps import event_monitor as evm
from wazuh_testing.modules.eps import ANALYSISD_STATE_INTERNAL_DEFAULT, PERCENTAGE_PROCESS_MSGS


pytestmark = [pytest.mark.server]

# Reference paths
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, 'configuration_template')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases')
# Configuration and cases data
configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_no_eps_configuration.yaml')
configurations_simulate_agent_path = os.path.join(TEST_DATA_PATH,
                                                  'configuration_simulate_agent.yaml')
t1_cases_path = os.path.join(TEST_CASES_PATH, 'cases_no_eps_configuration.yaml')

# Enabled test configurations (t1)
t1_configuration_parameters, t1_configuration_metadata, t1_case_ids = get_test_cases_data(t1_cases_path)
t1_configurations = load_configuration_template(configurations_path, t1_configuration_parameters,
                                                t1_configuration_metadata)

# Get simulate agent configurations (t1)
params_disabled_eps = get_simulate_agent_configuration(configurations_simulate_agent_path)
timeframe_eps_t1 = [metadata['timeframe'] for metadata in t1_configuration_metadata]
total_msg = 1000 # of 1Kb message of 16384 Kb of queue size
params_disabled_eps.update({'total_msg': total_msg})


@pytest.mark.parametrize('configuration, metadata', zip(t1_configurations, t1_configuration_metadata), ids=t1_case_ids)
@pytest.mark.parametrize('configure_local_internal_options_eps', [ANALYSISD_STATE_INTERNAL_DEFAULT], indirect=True)
def test_disabled(configuration, metadata, set_wazuh_configuration_eps,
                 truncate_monitored_files, restart_wazuh_daemon_function):
    '''
    description: Check that limits EPS is disabled when it is not configured.

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
        - The `cases_no_eps_configuration.yaml` file provides the module configuration for this test.

    expected_output:
        - r'(.*)wazuh-analysisd: INFO: EPS limit disabled'
    '''
    evm.check_eps_disabled()


@pytest.mark.parametrize('configuration, metadata', zip(t1_configurations, t1_configuration_metadata), ids=t1_case_ids)
@pytest.mark.parametrize('configure_local_internal_options_eps', [timeframe_eps_t1], indirect=True)
@pytest.mark.parametrize('simulate_agent', [params_disabled_eps], indirect=True)
def test_without_eps_setting(configuration, metadata, set_wazuh_configuration_eps,
                             truncate_monitored_files, restart_wazuh_daemon_function, simulate_agent):
    '''
    description: Check that limits EPS is disabled when it is not configured and the received events are similar or
                 equal to the processed events.

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
        - simulate_agent:
            type: fixture
            brief: Execute a script that simulate agent and send `logcolector` logs to the manager.

    assertions:
        - Verify the events_received are equal or greater than a porcentage of events_processed.

    input_description:
        - The `cases_disabled.yaml` file provides the module configuration for this test.

    expected_output:
        - r'(.*)wazuh-analysisd: INFO: EPS limit disabled'
    '''
    # Wait 'timeframe' / 2 second to read the wazuh-analysisd.state to ensure that has corrects values
    sleep(metadata['timeframe'] / 2)
    events_processed = evm.get_analysisd_state('events_processed')
    events_received = evm.get_analysisd_state('events_received')
    # There are some internal event that are processed but not are reflected in events_received, That why it has been used PERCENTAGE_PROCESS_MSGS variable
    assert events_processed >= events_received * PERCENTAGE_PROCESS_MSGS and \
           events_processed > 0, 'The events_processed value is similar to events_received'
