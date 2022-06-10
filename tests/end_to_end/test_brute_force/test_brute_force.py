import os
import pytest
from tempfile import gettempdir

from wazuh_testing.tools import configuration as config
from wazuh_testing import end_to_end as e2e
from wazuh_testing import event_monitor as evm

# Test cases data
alerts_json = os.path.join(gettempdir(), 'alerts.json')
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
test_cases_file_path = os.path.join(test_data_path, 'test_cases', 'cases_brute_force.yaml')

# Playbooks
configuration_playbooks = ['credentials.yaml']
events_playbooks = ['generate_events.yaml']

# Configuration
configurations, configuration_metadata, cases_ids = config.get_test_cases_data(test_cases_file_path)


@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
@pytest.mark.parametrize('metadata', configuration_metadata, ids=cases_ids)
def test_brute_force(configure_environment, metadata, get_dashboard_credentials, generate_events, clean_environment):
    """
    Test to detect a SSH Brute Force attack
    """
    rule_id = metadata['rule']['id']
    rule_level = metadata['rule']['level']
    rule_description = metadata['rule']['description']
    rule_mitre_technique = metadata['extra']['mitre_technique']

    expected_alert = r'\{{"timestamp":"(\d+\-\d+\-\w+\:\d+\:\d+\.\d+\+\d+)","rule"\:{{"level"\:{},"description"\:"{}",'\
                     r'"id"\:"{}".*\}}'.format(rule_level, rule_description, rule_id)

    query = e2e.make_query([
         {
            "term": {
               "rule.id": f"{rule_id}"
            }
         }
     ])
    indexed_alert = e2e.get_alert_indexer_api(query=query, credentials=get_dashboard_credentials).json()

    try:
        # Check that indexed alert has the correct rule id
        assert indexed_alert['hits']['hits'][0]['_source']['rule']['id'] == str(rule_id), 'Invalid rule id'
        # Check that indexed alert has the correct rule level
        assert indexed_alert['hits']['hits'][0]['_source']['rule']['level'] == rule_level, 'Invalid rule level'
        # Check that indexed alert has the correct rule description
        assert indexed_alert['hits']['hits'][0]['_source']['rule']['description'] == rule_description, 'Invalid description'
        # Check that indexed alert has the correct mitre technique
        assert indexed_alert['hits']['hits'][0]['_source']['rule']['mitre']['technique'][0] == rule_mitre_technique, 'Invalid mitre technique'
    except AssertionError:
        evm.check_event(callback=expected_alert, file_to_monitor=alerts_json, error_message='The alert has not occurred')
        raise AssertionError('The alert has occurred, but has not been indexed.')
