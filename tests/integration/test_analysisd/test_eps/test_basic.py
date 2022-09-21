import os
import pytest

from wazuh_testing.tools.configuration import load_configuration_template, get_test_cases_data
from wazuh_testing.modules.analysisd import event_monitor as evm
from wazuh_testing.modules.analysisd import ANALYSISD_STATE_INTERNAL_DEFAULT
from wazuh_testing.processes import check_if_daemons_are_running

pytestmark = [pytest.mark.server]


# Generic vars
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, 'configuration_template', 'basic_test_module')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases', 'basic_test_module')
local_internal_options = {'wazuh_modules.debug': '2', 'monitord.rotate_log': '0',
                          'analysisd.state_interval': f"{ANALYSISD_STATE_INTERNAL_DEFAULT}"}

# ------------------------------- TEST_ENABLED -------------------------------------------------------------------------
# Configuration and cases data
configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_enabled.yaml')
t1_cases_path = os.path.join(TEST_CASES_PATH, 'cases_enabled.yaml')

# Enabled test configurations (t1)
t1_configuration_parameters, t1_configuration_metadata, t1_case_ids = get_test_cases_data(t1_cases_path)
t1_configurations = load_configuration_template(configurations_path, t1_configuration_parameters,
                                                t1_configuration_metadata)

# ------------------------------- TEST_DISABLED ------------------------------------------------------------------------
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
                 configure_local_internal_options_module, truncate_monitored_files, restart_wazuh_daemon_function):
    evm.check_eps_enabled(metadata['maximum'], metadata['timeframe'])

    # Check that wazuh-analysisd is running
    assert check_if_daemons_are_running(['wazuh-analysisd'])[0], 'wazuh-analysisd is not running. Maybe it has crashed'


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('configuration, metadata', zip(t2_configurations, t2_configuration_metadata), ids=t2_case_ids)
def test_disabled(configuration, metadata, load_wazuh_basic_configuration, set_wazuh_configuration,
                  configure_local_internal_options_module, truncate_monitored_files, restart_wazuh_daemon_function):
    evm.check_eps_disabled()

    # Check that wazuh-analysisd is running
    assert check_if_daemons_are_running(['wazuh-analysisd'])[0], 'wazuh-analysisd is not running. Maybe it has crashed'
