import os
import pytest

from wazuh_testing.tools.configuration import load_configuration_template, get_test_cases_data
from wazuh_testing.modules.analysisd import event_monitor as evm
from wazuh_testing.modules.analysisd import ANALYSISD_STATE_INTERNAL_DEFAULT
from wazuh_testing.processes import check_if_daemons_are_running


pytestmark = [pytest.mark.server]

# Global variables
TIMEFRAME_DEFAULT_VALUE = 10
local_internal_options = {'wazuh_modules.debug': '2', 'monitord.rotate_log': '0',
                          'analysisd.state_interval': f"{ANALYSISD_STATE_INTERNAL_DEFAULT}"}

# Reference paths
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, 'configuration_template')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases')

# Configuration and cases data
t1_configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_without_timeframe.yaml')
t1_cases_path = os.path.join(TEST_CASES_PATH, 'cases_without_timeframe.yaml')

# Test configurations without timeframe value (t1)
t1_configuration_parameters, t1_configuration_metadata, t1_case_ids = get_test_cases_data(t1_cases_path)
t1_configurations = load_configuration_template(t1_configurations_path, t1_configuration_parameters,
                                                t1_configuration_metadata)


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('configuration, metadata', zip(t1_configurations, t1_configuration_metadata), ids=t1_case_ids)
def test_without_timeframe(configuration, metadata, load_wazuh_basic_configuration, set_wazuh_configuration,
                           configure_local_internal_options_module, truncate_monitored_files,
                           restart_wazuh_daemon_function):
    '''
    description: Check that limits EPS is started when `maximum` is set to a value greater than 0 lower and than 100000,
                 and `timeframe` is not present. In this case, 'timeframe' will be set with a default value.

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
        - Verify that the wazuh-analysisd daemon is running.

    input_description:
        - The `cases_without_timeframe.yaml` file provides the module configuration for this test.

    expected_output:
        - r'(.*)wazuh-analysisd: INFO: EPS limit enabled, EPS: (.*), timeframe: (.*)'
    '''
    evm.check_eps_enabled(metadata['maximum'], TIMEFRAME_DEFAULT_VALUE)

    # Check that wazuh-analysisd is running
    assert check_if_daemons_are_running(['wazuh-analysisd'])[0], 'wazuh-analysisd is not running. Maybe it has crashed'
