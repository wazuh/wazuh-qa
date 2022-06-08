import os
import pytest
from tempfile import gettempdir

from wazuh_testing.tools import configuration as config
from wazuh_testing.end_to_end import get_alert_indexer_api, make_query
from wazuh_testing.event_monitor import check_event


alerts_json = os.path.join(gettempdir(), 'alerts.json')
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
test_cases_file_path = os.path.join(test_data_path, 'test_cases', 'cases_audit.yml')
configuration_playbooks = ['configuration.yaml', 'credentials.yaml']
events_playbooks = ['generate_events.yaml']

configurations, configuration_metadata, cases_ids = config.get_test_cases_data(test_cases_file_path)


@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
@pytest.mark.parametrize('metadata', configuration_metadata, ids=cases_ids)
def test_audit(configure_environment, metadata, get_dashboard_credentials, generate_events, clean_environment):

    level = metadata['level']
    description = metadata['description']
    rule_id = metadata['rule.id']
    euid = metadata['extra']['euid']
    a3 = metadata['extra']['a3']
    data_audit_command = metadata['extra']['data.audit.command']

    expected_alert = r'\{{"timestamp":"(\d+\-\d+\-\w+\:\d+\:\d+\.\d+\+\d+)","rule"\:{{"level"\:{},"description"\:"{}",'\
                     r'"id"\:"{}".*euid={}.*a3={}.*\}}'.format(level, description, rule_id, euid, a3)

    query = make_query([
         {
            "term": {
               "rule.id": f"{rule_id}"
            }
         },
         {
            "term": {
               "data.audit.command": f"{data_audit_command}"
            }
         }
     ])
    indexed_alert = get_alert_indexer_api(query=query, credentials=get_dashboard_credentials)

    try:
        assert str(rule_id) in indexed_alert.text
    except AssertionError:
        check_event(callback=expected_alert, file_to_monitor=alerts_json, error_message='The alert has not occurred')
        raise AssertionError('The alert has occurred, but has not been indexed.')
