import os
import pytest

from wazuh_testing.tools.configuration import load_configuration_template, get_test_cases_data
from wazuh_testing.modules.analysisd import event_monitor as evm
from wazuh_testing.processes import check_if_daemons_are_running

pytestmark = [pytest.mark.server]


# Generic vars
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, 'configuration_template', 'basic_test_module')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases', 'basic_test_module')
local_internal_options = {'wazuh_modules.debug': '2', 'monitord.rotate_log': '0'}

# ---------------------------------------------------- TEST_ENABLED ----------------------------------------------------
# Configuration and cases data
configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_enabled.yaml')
t1_cases_path = os.path.join(TEST_CASES_PATH, 'cases_enabled.yaml')

# Enabled test configurations (t1)
t1_configuration_parameters, t1_configuration_metadata, t1_case_ids = get_test_cases_data(t1_cases_path)
t1_configurations = load_configuration_template(configurations_path, t1_configuration_parameters,
                                                t1_configuration_metadata)

# ---------------------------------------------------- TEST_DISABLED ---------------------------------------------------
# Configuration and cases data
t2_configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_disabled.yaml')
t2_cases_path = os.path.join(TEST_CASES_PATH, 'cases_disabled.yaml')

# Disabled test configurations (t2)
t2_configuration_parameters, t2_configuration_metadata, t2_case_ids = get_test_cases_data(t2_cases_path)
t2_configurations = load_configuration_template(t2_configurations_path, t2_configuration_parameters,
                                                t2_configuration_metadata)


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('configuration, metadata', zip(t1_configurations, t1_configuration_metadata), ids=t1_case_ids)
def test_enabled(configuration, metadata, load_wazuh_basic_configuration, set_wazuh_configuration,
                 configure_local_internal_options_function, truncate_monitored_files, restart_wazuh_daemon_function):
    """
    description: Check whether the event analysis limitation is activated after its activation in the configuration.

    test_phases:
        - setup:
            - Load Wazuh light configuration.
            - Apply ossec.conf configuration changes according to the configuration template and use case.
            - Apply custom settings in local_internal_options.conf.
            - Truncate wazuh logs.
            - Restart wazuh-manager service to apply configuration changes.
        - test:
            - Check in the ossec.log that a line has appeared indicating that EPS limiting has been enabled.
            - Check that wazuh-analysisd is running (it has not been crashed).
        - teardown:
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
        - Check in the log that the EPS limitation has been activated.
        - Check that wazuh-analysisd daemon does not crash.

    input_description:
        - The `configuration_enabled` file provides the module configuration for this test.
        - The `cases_enabled` file provides the test cases.
    """
    evm.check_eps_enabled(metadata['maximum'], metadata['timeframe'])

    # Check that wazuh-analysisd is running
    assert check_if_daemons_are_running(['wazuh-analysisd'])[0], 'wazuh-analysisd is not running. Maybe it has crashed'


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('configuration, metadata', zip(t2_configurations, t2_configuration_metadata), ids=t2_case_ids)
def test_disabled(configuration, metadata, load_wazuh_basic_configuration, set_wazuh_configuration,
                  configure_local_internal_options_function, truncate_monitored_files, restart_wazuh_daemon_function):
    """
    description: Check if when the EPS limitation setting is not applied, the feature is not activated.

    test_phases:
        - setup:
            - Load Wazuh light configuration.
            - Apply ossec.conf configuration changes according to the configuration template and use case.
            - Apply custom settings in local_internal_options.conf.
            - Truncate wazuh logs.
            - Restart wazuh-manager service to apply configuration changes.
        - test:
            - Look in the ossec.log to see if the EPS limitation activation does not appear.
            - Check that wazuh-analysisd is running (it has not been crashed).
        - teardown:
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
        - Check in the ossec.log to see if the EPS limitation activation does not appear.
        - Check that wazuh-analysisd daemon does not crash.

    input_description:
        - The `configuration_disabled` file provides the module configuration for this test.
        - The `cases_disabled` file provides the test cases.
    """
    evm.check_eps_disabled()

    # Check that wazuh-analysisd is running
    assert check_if_daemons_are_running(['wazuh-analysisd'])[0], 'wazuh-analysisd is not running. Maybe it has crashed'
