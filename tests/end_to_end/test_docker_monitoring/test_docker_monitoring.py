import json
import os
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
    expected_api_alert = f".+Action.+{docker_action}.+level.+{rule_level}.+description.+{rule_description}.+" \
                         f"id.+{rule_id}.+"
    expected_log_alert = f".+level.+{rule_level}.+description.+{rule_description}.+id.+{rule_id}.+" \
                         f"Action.+{docker_action}.+"

    query = e2e.make_query([
        {
            "term": {
                "rule.id": rule_id
            }
        },
        {
            "term": {
                "rule.description": rule_description
            }
        },
        {
            "term": {
                "data.docker.Action": docker_action
            }
        }
    ])

    response = e2e.get_alert_indexer_api(query=query, credentials=get_dashboard_credentials)
    assert response.status_code == 200, f"The response is not the expected. Actual response {response.text}"

    indexed_alert = json.dumps(response.json())

    try:
        match = re.search(expected_api_alert, indexed_alert)
        assert match is not None, 'The alert was triggered but not indexed.'
    except AssertionError as exc:
        err_msg = 'The alert was not triggered.'
        evm.check_event(callback=expected_log_alert, file_to_monitor=alerts_json, error_message=err_msg)
        raise AssertionError(exc.args[0])
