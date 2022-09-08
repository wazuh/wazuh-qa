import os
import pytest

from wazuh_testing.tools.configuration import load_configuration_template, get_test_cases_data
from wazuh_testing.modules.analysisd import event_monitor as evm
from wazuh_testing.modules.analysisd import ANALYSISD_STATE_INTERNAL_DEFAULT
from wazuh_testing.processes import check_if_daemons_are_running


pytestmark = [pytest.mark.server]

# Reference paths
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, 'configuration_template')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases')
local_internal_options = {'wazuh_modules.debug': '2', 'monitord.rotate_log': '0',
                          'analysisd.state_interval': f"{ANALYSISD_STATE_INTERNAL_DEFAULT}"}

# Configuration and cases data
t1_configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_disabled.yaml')
t1_cases_path = os.path.join(TEST_CASES_PATH, 'cases_disabled.yaml')

t2_configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_without_maximum.yaml')
t2_cases_path = os.path.join(TEST_CASES_PATH, 'cases_without_maximum.yaml')

# Disabled test configurations (t1)
t1_configuration_parameters, t1_configuration_metadata, t1_case_ids = get_test_cases_data(t1_cases_path)
t1_configurations = load_configuration_template(t1_configurations_path, t1_configuration_parameters,
                                                t1_configuration_metadata)

# Test configurations without maximum value (t2)
t2_configuration_parameters, t2_configuration_metadata, t2_case_ids = get_test_cases_data(t2_cases_path)
t2_configurations = load_configuration_template(t2_configurations_path, t2_configuration_parameters,
                                                t2_configuration_metadata)


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('configuration, metadata', zip(t1_configurations, t1_configuration_metadata), ids=t1_case_ids)
def test_disabled(configuration, metadata, load_wazuh_basic_configuration, set_wazuh_configuration,
                  configure_local_internal_options_module, truncate_monitored_files, restart_wazuh_daemon_function):
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
        - Verify that when the `maximum` value is set to 0 or with an empty value and, `timeframe` value is set to a
          value greater than 0 and lower than 3600, the module EPS limits is not running.
        - Verify that the wazuh-analysisd daemon is running.

    input_description:
        - The `cases_disabled.yaml` file provides the module configuration for this test.

    expected_output:
        - r'(.*)wazuh-analysisd: INFO: EPS limit disabled'
    '''
    evm.check_eps_disabled()

    # Check that wazuh-analysisd is running
    assert check_if_daemons_are_running(['wazuh-analysisd'])[0], 'wazuh-analysisd is not running. Maybe it has crashed'


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('configuration, metadata', zip(t2_configurations, t2_configuration_metadata), ids=t2_case_ids)
def test_without_maximum(configuration, metadata, load_wazuh_basic_configuration, set_wazuh_configuration,
                         configure_local_internal_options_module, truncate_monitored_files,
                         restart_wazuh_daemon_function):
    '''
    description: Check that limits EPS is not started when `maximum` value is not present in the configuration
                 file.

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
        - Verify that when the `maximum` is not present, the EPS module is disabled.
        - Verify that the wazuh-analysisd daemon is running.

    input_description:
        - The `cases_without_maximun.yaml` file provides the module configuration for this test.

    expected_output:
        - r'(.*)wazuh-analysisd: INFO: EPS limit disabled'
    '''
    evm.check_eps_disabled()

    # Check that wazuh-analysisd is running
    assert check_if_daemons_are_running(['wazuh-analysisd'])[0], 'wazuh-analysisd is not running. Maybe it has crashed'
