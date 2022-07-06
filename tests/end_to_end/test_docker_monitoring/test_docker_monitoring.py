import os
import json
import re
import pytest
from tempfile import gettempdir

from wazuh_testing import end_to_end as e2e
from wazuh_testing import event_monitor as evm
from wazuh_testing.tools import configuration as config

# Test cases data
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
test_cases_path = os.path.join(test_data_path, 'test_cases')
test_cases_file_path = os.path.join(test_cases_path, 'cases_docker_monitoring.yaml')
alerts_json = os.path.join(gettempdir(), 'alerts.json')

# Playbooks
configuration_playbooks = ['configuration.yaml']
events_playbooks = ['generate_events.yaml']

# Configuration
configurations, configuration_metadata, cases_ids = config.get_test_cases_data(test_cases_file_path)


@pytest.mark.parametrize('metadata', configuration_metadata, ids=cases_ids)
@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
def test_docker_monitoring(configure_environment, metadata, get_dashboard_credentials, generate_events,
                           clean_environment):
    rule_description = metadata['rule.description']
    rule_id = metadata['rule.id']
    rule_level = metadata['rule.level']
    docker_action = metadata['extra']['data.docker.Action']

    expected_alert_json = fr".+timestamp\":\"(.+)\",.+level.+{rule_level}.+description.+{rule_description}.+" \
                          fr"id.+{rule_id}.+Action.+{docker_action}.+"

    expected_indexed_alert = fr".+Action.+{docker_action}.+level.+{rule_level}.+description.+{rule_description}.+" \
                             fr"id.+{rule_id}.+timestamp\": \"(.+)\"" \
                             r'},.+'

    # Check that alert has been raised and save timestamp
    raised_alert = evm.check_event(callback=expected_alert_json, file_to_monitor=alerts_json,
                                   error_message='The alert has not occurred').result()
    raised_alert_timestamp = raised_alert.group(1)

    query = e2e.make_query([
        {
            "term": {
                "rule.id": f"{rule_id}"
            }
        },
        {
            "term": {
                "rule.description": f"{rule_description}"
            }
        },
        {
            "term": {
                "data.docker.Action": f"{docker_action}"
            }
        },
        {
            "term": {
                "timestamp": f"{raised_alert_timestamp}"
            }
        }
    ])

    # Get indexed alert
    response = e2e.get_alert_indexer_api(query=query, credentials=get_dashboard_credentials)
    indexed_alert = json.dumps(response.json())

    # Check that the alert data is the expected one
    alert_data = re.search(expected_indexed_alert, indexed_alert)
    assert alert_data is not None, 'Alert triggered, but not indexed'
