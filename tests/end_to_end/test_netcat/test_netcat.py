import os
import pytest
import re
import json
from tempfile import gettempdir

from wazuh_testing.tools import configuration as config
from wazuh_testing import end_to_end as e2e
from wazuh_testing import event_monitor as evm

## Test cases data
alerts_json = os.path.join(gettempdir(), 'alerts.json')
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
test_cases_file_path = os.path.join(test_data_path, 'test_cases', 'cases_netcat.yaml')

# Playbooks
configuration_playbooks = ['configuration.yaml', 'credentials.yaml']
events_playbooks = ['generate_events.yaml']

#Configuration
configurations, configuration_metadata, cases_ids = config.get_test_cases_data(test_cases_file_path)


@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
@pytest.mark.parametrize('metadata', configuration_metadata, ids=cases_ids)
def test_audit(configure_environment, metadata, get_dashboard_credentials, generate_events, clean_environment):
    level = metadata['rule']['level']
    description = metadata['rule']['description']
    rule_id = metadata['rule']['id']

    expected_alert = r'\{{"timestamp":"(\d+\-\d+\-\w+\:\d+\:\d+\.\d+\+\d+)","rule"\:{{"level"\:{},"description"\:"{}",'\
                     r'"id"\:"{}".*\}}'.format(level, description, rule_id)
    expected_api_alert = f".+\"description\": \"({description})\".+\"id\": " \
                         f"\"({rule_id})\""

    query = e2e.make_query([
         {
            "term": {
               "rule.id": f"{rule_id}"
            }
         }
     ])
    response = e2e.get_alert_indexer_api(query=query, credentials=get_dashboard_credentials)
    assert response.status_code == 200, f"The response is not the expected. Actual response {response.text}"

    indexed_alert = json.dumps(response.json())

    try:
        match = re.search(expected_api_alert, indexed_alert)
        assert match is not None, 'The alert was triggered but not indexed'
    except AssertionError as exc:
        err_msg = 'THe alert was not triggered'
        evm.check_event(callback=expected_alert, file_to_monitor=alerts_json, error_message='The alert has not occurred')
        raise AssertionError(exc.args[0])
