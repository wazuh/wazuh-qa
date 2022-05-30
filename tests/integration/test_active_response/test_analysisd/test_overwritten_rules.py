import os
import pytest

from wazuh_testing.tools.configuration import load_configuration_template, get_test_cases_data

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
source_path = [custom_rule, local_rules]

# Test configurations
configuration_parameters, configuration_metadata, case_ids = get_test_cases_data(cases_path)
configurations = load_configuration_template(configurations_path, configuration_parameters, configuration_metadata)

@pytest.mark.parametrize("source_path", [source_path])
@pytest.mark.parametrize("destination_path", ['/var/ossec/etc/rules'])
@pytest.mark.parametrize("daemon", ['wazuh-analysisd'])
@pytest.mark.parametrize('configuration, metadata', zip(configurations, configuration_metadata), ids=case_ids)
def test_overwritten_rules(configuration, metadata, set_wazuh_configuration_analysisd, copy_file, source_path,
                           destination_path, restart_wazuh_daemon, daemon):
    pass
    ## verify that the Analysis daemon starts as expected and Active Response works for rules 100001, 100002, and 100004.
