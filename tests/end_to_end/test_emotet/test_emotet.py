import json
import os
import re
import pytest
from tempfile import gettempdir

from wazuh_testing import end_to_end as e2e
from wazuh_testing import event_monitor as evm
from wazuh_testing.tools import configuration as config


alerts_json = os.path.join(gettempdir(), 'alerts.json')
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
test_cases_file_path = os.path.join(test_data_path, 'test_cases', 'cases_emotet.yaml')
configuration_playbooks = ['configuration.yaml']
emotet_file_path = os.path.join(test_data_path, 'configuration', 'trigger-emotet.exe')
sysmon_config = os.path.join(test_data_path, 'configuration', 'sysconfig.xml')
configuration_extra_vars = {'emotet_file': emotet_file_path, 'sysmon_config': sysmon_config}
events_playbooks = ['generate_events.yaml']
teardown_playbooks = ['teardown.yaml']

# Configuration
configurations, configuration_metadata, cases_ids = config.get_test_cases_data(test_cases_file_path)


@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
@pytest.mark.parametrize('metadata', configuration_metadata, ids=cases_ids)
def test_emotet(configure_environment, metadata, get_dashboard_credentials, generate_events, clean_alerts_index):
    """
    Test to detect an emotet attack
    """
    regsvr32_alert = metadata['regsvr32']
    word_executing_script_alert = metadata['word_executing_script']
    expected_alerts = [regsvr32_alert, word_executing_script_alert]

    for alert in expected_alerts:
        rule_level = alert['rule.level']
        rule_id = alert['rule.id']
        rule_description = alert['rule.description']
        rule_groups = alert['extra']['groups']

        expected_alert_json = fr'\{{"timestamp":"(\d+\-\d+\-\w+\:\d+\:\d+\.\d+\+\d+)",' \
                              fr'"rule"\:{{"level"\:{rule_level},' \
                              fr'"description"\:"{rule_description}","id"\:"{rule_id}".*' \
                              fr'"groups"\:\["{rule_groups}"\].*\}}'

        expected_indexed_alert = fr'.*"rule":.*"level": {rule_level}, "description": "{rule_description}".*'\
                                 fr'"groups": \["{rule_groups}"\].*"id": "{rule_id}".*' \
                                 r'"timestamp": "(\d+\-\d+\-\w+\:\d+\:\d+\.\d+\+\d+)".*'

        # Check that alert has been raised and save timestamp
        raised_alert = evm.check_event(callback=expected_alert_json, file_to_monitor=alerts_json,
                                       error_message=f"The alert '{rule_description}' has not occurred").result()
        raised_alert_timestamp = raised_alert.group(1)

        query = e2e.make_query([
            {
                "term": {
                    "rule.id": f"{rule_id}"
                }
            },
            {
                "term": {
                    "timestamp": f"{raised_alert_timestamp}"
                }
            }
        ])

        # Check if the alert has been indexed and get its data
        response = e2e.get_alert_indexer_api(query=query, credentials=get_dashboard_credentials)
        indexed_alert = json.dumps(response.json())

        # Check that the alert data is the expected one
        alert_data = re.search(expected_indexed_alert, indexed_alert)
        assert alert_data is not None, f"Alert '{rule_description}' triggered, but not indexed"
