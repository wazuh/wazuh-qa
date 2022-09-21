import os
import pytest

from wazuh_testing.tools.configuration import load_configuration_template, get_test_cases_data
from wazuh_testing.modules.analysisd import event_monitor as evm
from wazuh_testing.tools.services import control_service
from wazuh_testing.modules.analysisd import ANALYSISD_STATE_INTERNAL_DEFAULT
from wazuh_testing.processes import check_if_daemons_are_running
from wazuh_testing.tools import file
from wazuh_testing import WAZUH_CONF_PATH

# Reference paths
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, 'configuration_template', 'configuration_test_module')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases', 'configuration_test_module')
local_internal_options = {'wazuh_modules.debug': '2', 'monitord.rotate_log': '0',
                          'analysisd.state_interval': f"{ANALYSISD_STATE_INTERNAL_DEFAULT}"}

# ------------------------------- TEST_ACCEPTED_VALUES -------------------------------------------------------------------
# Configuration and cases data
t1_configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_accepted_values.yaml')
t1_cases_path = os.path.join(TEST_CASES_PATH, 'cases_accepted_values.yaml')

# Accepted values test configurations (t1)
t1_configuration_parameters, t1_configuration_metadata, t1_case_ids = get_test_cases_data(t1_cases_path)
t1_configurations = load_configuration_template(t1_configurations_path, t1_configuration_parameters,
                                                t1_configuration_metadata)

# ------------------------------- TEST_INVALID_VALUES ------------------------------------------------------------------
# Configuration and cases data
t2_configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_invalid_values.yaml')
t2_cases_path = os.path.join(TEST_CASES_PATH, 'cases_invalid_values.yaml')

# Invalid values test configurations (t2)
t2_configuration_parameters, t2_configuration_metadata, t2_case_ids = get_test_cases_data(t2_cases_path)
t2_configurations = load_configuration_template(t2_configurations_path, t2_configuration_parameters,
                                                t2_configuration_metadata)

# ------------------------------- TEST_MISSING_CONFIGURATION -----------------------------------------------------------
# Configuration and cases data
t3_configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_missing_configuration.yaml')
t3_cases_path = os.path.join(TEST_CASES_PATH, 'cases_missing_configuration.yaml')

# Invalid values test configurations (t2)
t3_configuration_parameters, t3_configuration_metadata, t3_case_ids = get_test_cases_data(t3_cases_path)
t3_configurations = load_configuration_template(t3_configurations_path, t3_configuration_parameters,
                                                t3_configuration_metadata)


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('configuration, metadata', zip(t1_configurations, t1_configuration_metadata), ids=t1_case_ids)
def test_accepted_values(configuration, metadata, load_wazuh_basic_configuration, set_wazuh_configuration,
                         configure_local_internal_options_module, truncate_monitored_files,
                         restart_wazuh_daemon_function):

    evm.check_eps_enabled(metadata['maximum'], metadata['timeframe'])

    # Check that wazuh-analysisd is running
    assert check_if_daemons_are_running(['wazuh-analysisd'])[0], 'wazuh-analysisd is not running. Maybe it has crashed'


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('configuration, metadata', zip(t2_configurations, t2_configuration_metadata), ids=t2_case_ids)
def test_invalid_values(configuration, metadata, restart_wazuh_daemon_after_finishing_function,
                        load_wazuh_basic_configuration, set_wazuh_configuration,
                        configure_local_internal_options_module, truncate_monitored_files):
    try:
        control_service('restart')
    except ValueError:
        pass
    finally:
        evm.check_configuration_error()
        # Check that wazuh-analysisd is not running
        assert not check_if_daemons_are_running(['wazuh-analysisd'])[0], 'wazuh-analysisd is running and was not ' \
                                                                            'expected to'


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('configuration, metadata', zip(t3_configurations, t3_configuration_metadata), ids=t3_case_ids)
def test_missing_configuration(configuration, metadata, restart_wazuh_daemon_after_finishing_function,
                               load_wazuh_basic_configuration, set_wazuh_configuration,
                               truncate_monitored_files):

    # Remove test case tags from ossec.conf
    file.replace_regex_in_file(metadata['remove_tags'], [''] * len(metadata['remove_tags']), WAZUH_CONF_PATH)

    if metadata['behavior'] == 'works':
        control_service('restart')
        evm.check_eps_enabled(metadata['maximum'], 10)  # 10 is the default timeframe
    elif metadata['behavior'] == 'disabled':
        control_service('restart')
        evm.check_eps_disabled()
    else:
        try:
            control_service('restart')
        except ValueError:
            pass
        finally:
            evm.check_configuration_error()
            # Check that wazuh-analysisd is not running
            assert not check_if_daemons_are_running(['wazuh-analysisd'])[0], 'wazuh-analysisd is running and was not ' \
                                                                                'expected to'
