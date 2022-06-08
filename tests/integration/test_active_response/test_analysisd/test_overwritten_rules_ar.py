import os
import pytest

from wazuh_testing.processes import check_if_analysisd_is_running
from wazuh_testing.tools.configuration import load_configuration_template, get_test_cases_data
from wazuh_testing.tools.file import write_file
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools import CUSTOM_RULES_PATH, LOCAL_RULES_PATH, AR_SCRIPTS_PATH
import wazuh_testing.execd as execd

# Reference paths
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, 'configuration_template')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases')
RULES_PATH = os.path.join(TEST_DATA_PATH, 'rules')

# Configuration and cases data
configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_overwritten_rules.yaml')
cases_path = os.path.join(TEST_CASES_PATH, 'cases_overwritten_rules.yaml')
custom_rule = os.path.join(RULES_PATH, '0270-web_appsec_rules_edit.xml')
local_rules = os.path.join(RULES_PATH, 'local_rules.xml')
output_custom_ar_script = '/tmp/file-ar.txt'
source_path = [custom_rule, local_rules]
destination_path = [f"{CUSTOM_RULES_PATH}/0270-web_appsec_rules_edit.xml", LOCAL_RULES_PATH, f"{AR_SCRIPTS_PATH}/custom-ar.py"]

AR_timeout = 10

# Test configurations
configuration_parameters, configuration_metadata, case_ids = get_test_cases_data(cases_path)
configurations = load_configuration_template(configurations_path, configuration_parameters, configuration_metadata)

@pytest.mark.parametrize("source_path", [source_path])
@pytest.mark.parametrize("destination_path", [destination_path])
@pytest.mark.parametrize("file_to_monitor", ['/tmp/file_to_monitor.log'])
@pytest.mark.parametrize('configuration, metadata', zip(configurations, configuration_metadata), ids=case_ids)
def test_overwritten_rules_ar(configuration, metadata, create_file_to_monitor, file_to_monitor,
                              set_wazuh_configuration_analysisd, copy_file, source_path, destination_path,
                              restart_wazuh_daemon):
    write_file(file_to_monitor, metadata['log_sample'])

    ar_log_monitor = FileMonitor(execd.AR_LOG_FILE_PATH)

    # Checking if AR works properly
    assert os.path.exists(output_custom_ar_script)

    # Check that wazuh-analysisd is running and has not crashed when trying to parse files with unexpected file types
    check_if_analysisd_is_running()

    execd.clean_logs()
