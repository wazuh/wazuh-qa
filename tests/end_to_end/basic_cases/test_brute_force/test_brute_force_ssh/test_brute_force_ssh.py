import os
import json
import re
import pytest
from tempfile import gettempdir

import wazuh_testing as fw
from wazuh_testing.tools import configuration as config
from wazuh_testing import end_to_end as e2e
from wazuh_testing import event_monitor as evm

# Test cases data
alerts_json = os.path.join(gettempdir(), 'alerts.json')
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
test_cases_file_path = os.path.join(test_data_path, 'test_cases', 'cases_brute_force_ssh.yaml')

# Playbooks
events_playbooks = ['generate_events.yaml']
teardown_playbooks = None

# Configuration
configurations, configuration_metadata, cases_ids = config.get_test_cases_data(test_cases_file_path)


@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
@pytest.mark.parametrize('metadata', configuration_metadata, ids=cases_ids)
def test_brute_force_ssh(metadata, get_dashboard_credentials, generate_events, clean_alerts_index):
    """
    Test to detect a SSH Brute Force attack
    """
    rule_id = metadata['rule.id']
    rule_level = metadata['rule.level']
    rule_description = metadata['rule.description']
    rule_mitre_technique = metadata['extra']['mitre_technique']
    timestamp = r'\d+-\d+-\d+T\d+:\d+:\d+\.\d+[+|-]\d+'

    expected_alert_json = fr'\{{"timestamp":"({timestamp})","rule"\:{{"level"\:{rule_level},' \
                          fr'"description"\:"{rule_description}","id"\:"{rule_id}".*'

    expected_indexed_alert = fr'.*"rule":.*"level": {rule_level},.*"description": "{rule_description}"' \
                             fr'.*"mitre":.*"{rule_mitre_technique}".*"id": "{rule_id}".*'

    # Check that alert has been raised and save timestamp
    raised_alert = evm.check_event(callback=expected_alert_json, file_to_monitor=alerts_json,
                                   timeout=fw.T_5, error_message='The alert has not occurred').result()
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
    assert alert_data is not None, 'Alert triggered, but not indexed'
