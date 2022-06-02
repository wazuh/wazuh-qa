import os
import pytest
from random import randint

import wazuh_testing.execd as execd
from wazuh_testing.tools.configuration import load_configuration_template, get_test_cases_data
from wazuh_testing.tools.file import write_file
from wazuh_testing.tools.monitoring import FileMonitor, generate_monitoring_callback
from wazuh_testing.tools import WAZUH_PATH, LOG_FILE_PATH

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
destination_path = [f"/var/ossec/etc/rules/0270-web_appsec_rules_edit.xml", f"/var/ossec/etc/rules/local_rules.xml"]

ip = ".".join(str(randint(0, 255)) for _ in range(4))
log_sample = f"Dec  9 22:15:40 localhost sshd[5332]: Failed password for invalid user BALROG from {ip} port 52620 '$token': `132`! ssh2\n\n"

# Test configurations
configuration_parameters, configuration_metadata, case_ids = get_test_cases_data(cases_path)
configurations = load_configuration_template(configurations_path, configuration_parameters, configuration_metadata)


@pytest.mark.parametrize("source_path", [source_path])
@pytest.mark.parametrize("destination_path", [destination_path])
@pytest.mark.parametrize('configuration, metadata', zip(configurations, configuration_metadata), ids=case_ids)
def test_overwritten_rules(configuration, metadata, set_wazuh_configuration_analysisd, copy_file, source_path,
                           destination_path, restart_wazuh_daemon):
    
    write_file('/var/log/secure', log_sample)

    ossec_log_monitor = FileMonitor(LOG_FILE_PATH)
    ar_log_monitor = FileMonitor(execd.AR_LOG_FILE_PATH)

    # Checking AR in active-response logs
    ar_log_monitor.start(timeout=60, callback=execd.wait_start_message_line)
    ar_log_monitor.start(timeout=60, callback=execd.wait_message_line)

    # Checking shutdown message in ossec logs
    ossec_log_monitor.start(timeout=60, callback=generate_monitoring_callback('Shutdown received. Deleting responses.'))

    ar_log_monitor.start(timeout=60, callback=execd.wait_ended_message_line)
    ## verify that the Analysis daemon starts as expected and Active Response works for rules 100001, 100002, and 100004.
