import os
import pytest

from wazuh_testing.tools.configuration import load_configuration_template, get_test_cases_data
from wazuh_testing.modules.eps import event_monitor as evm
from wazuh_testing.modules.eps import ANALYSISD_STATE_INTERNAL_DEFAULT
from wazuh_testing.processes import check_if_deamon_is_running


pytestmark = [pytest.mark.server]

# Reference paths
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, 'configuration_template')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases')

# Configuration and cases data
configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_enabled.yaml')
t1_cases_path = os.path.join(TEST_CASES_PATH, 'cases_enabled.yaml')

# Enabled test configurations (t1)
t1_configuration_parameters, t1_configuration_metadata, t1_case_ids = get_test_cases_data(t1_cases_path)
t1_configurations = load_configuration_template(configurations_path, t1_configuration_parameters,
                                                t1_configuration_metadata)


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('configuration, metadata', zip(t1_configurations, t1_configuration_metadata), ids=t1_case_ids)
@pytest.mark.parametrize('configure_local_internal_options_eps', [ANALYSISD_STATE_INTERNAL_DEFAULT], indirect=True)
def test_enabled(configuration, metadata, load_wazuh_basic_configuration, set_wazuh_configuration_eps,
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
        - load_wazuh_basic_configuration
            type: fixture
            brief: Load a basic configuration to the manager.
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
        - Verify that the wazuh-analysisd daemon is running.

    input_description:
        - The `cases_enabled.yaml` file provides the module configuration for this test.

    expected_output:
        - r'(.*)wazuh-analysisd: INFO: EPS limit enabled, EPS: (.*), timeframe: (.*)'
    '''
    evm.check_eps_enabled(metadata['maximum'], metadata['timeframe'])
    # Check that wazuh-analysisd is running
    check_if_deamon_is_running('wazuh-analysisd')
