import os
from time import sleep
import pytest

from wazuh_testing.tools.configuration import get_simulate_agent_configuration
from wazuh_testing.modules.eps import event_monitor as evm
from wazuh_testing.modules.analysisd import ANALYSISD_STATE_INTERNAL_DEFAULT, PERCENTAGE_PROCESS_MSGS


pytestmark = [pytest.mark.server]

# Reference paths
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
# Simulate agent configuration
configurations_simulate_agent_path = os.path.join(TEST_DATA_PATH,
                                                  'configuration_simulate_agent.yaml')

# Get simulate agent configurations (t1)
params_disabled_eps = get_simulate_agent_configuration(configurations_simulate_agent_path)
num_messages = 1000  # of 1Kb message of 16384 Kb of queue size
params_disabled_eps.update({'num_messages': num_messages})


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('configure_local_internal_options_eps', [ANALYSISD_STATE_INTERNAL_DEFAULT], indirect=True)
def test_disabled(load_wazuh_basic_configuration, configure_local_internal_options_eps,
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
        - load_wazuh_basic_configuration
            type: fixture
            brief: Load a basic configuration to the manager.
        - configure_local_internal_options_eps:
            type: fixture
            brief: Set the wazuh local internal option configuration.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate all the log files and json alerts files before and after the test execution.
        - restart_wazuh_daemon_function:
            type: fixture
            brief: Restart all the wazuh daemons.

    expected_output:
        - r'(.*)wazuh-analysisd: INFO: EPS limit disabled'
    '''
    evm.check_eps_disabled()


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('configure_local_internal_options_eps', [ANALYSISD_STATE_INTERNAL_DEFAULT], indirect=True)
@pytest.mark.parametrize('simulate_agent_function', [params_disabled_eps], indirect=True)
def test_without_eps_setting(load_wazuh_basic_configuration, configure_local_internal_options_eps,
                             truncate_monitored_files, restart_wazuh_daemon_function, simulate_agent_function):
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
        - load_wazuh_basic_configuration
            type: fixture
            brief: Load a basic configuration to the manager.
        - configure_local_internal_options_eps:
            type: fixture
            brief: Set the wazuh local internal option configuration.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate all the log files and json alerts files before and after the test execution.
        - restart_wazuh_daemon_function:
            type: fixture
            brief: Restart all the wazuh daemons.
        - simulate_agent_function:
            type: fixture
            brief: Execute a script that simulate agent and send `logcolector` logs to the manager.

    assertions:
        - Verify the events received are equal or greater than a porcentage of events processed.
    '''
    # Wait ANALYSISD_STATE_INTERNAL_DEFAULT / 2 second to read the wazuh-analysisd.state to ensure corrects values
    sleep(int(ANALYSISD_STATE_INTERNAL_DEFAULT) / 2)
    analysisd_state = evm.get_analysisd_state()
    events_processed = int(analysisd_state['events_processed'])
    events_received = int(analysisd_state['events_received'])
    # There are some internal event that are processed but are not reflected in events_received, That why it
    # has been used PERCENTAGE_PROCESS_MSGS variable
    assert events_processed >= events_received * PERCENTAGE_PROCESS_MSGS and events_processed > 0, 'The ' \
        'events_processed value is similar to events_received'
