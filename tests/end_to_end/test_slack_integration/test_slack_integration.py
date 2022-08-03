import os
import json
import re
import pytest
from tempfile import gettempdir

import wazuh_testing as fw
from wazuh_testing.tools.file import remove_file
from wazuh_testing import end_to_end as e2e
from wazuh_testing import event_monitor as evm
from wazuh_testing.tools import configuration as config

# Test cases data
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
test_cases_path = os.path.join(test_data_path, 'test_cases')
test_cases_file_path = os.path.join(test_cases_path, 'cases_slack_integration.yaml')
alerts_json = os.path.join(gettempdir(), 'alerts.json')

# Playbooks
configuration_playbooks = ['configuration.yaml']
events_playbooks = ['generate_events.yaml']
teardown_playbooks = ['teardown.yaml']

# Configuration
configuration, metadata, cases_ids = config.get_test_cases_data(test_cases_file_path)

# Custom paths
slack_api_script = os.path.join(test_data_path, 'configuration', 'slack_api_script.py')

# Update configuration with custom paths
metadata = config.update_configuration_template(metadata, ['CUSTOM_SLACK_SCRIPT_PATH'], [slack_api_script])


@pytest.fixture(scope='function')
def get_slack_log_path():
    """Get the temporary path to the file containing the Slack messages. Then delete the temporary file.

    Returns:
        slack_messages_log(str): String with the file path.
    """

    slack_messages_log = os.path.join(gettempdir(), 'slack_messages.log')

    yield slack_messages_log

    remove_file(slack_messages_log)


@pytest.mark.parametrize('metadata', metadata, ids=cases_ids)
@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
def test_slack_integration(metadata, configure_environment, get_dashboard_credentials, generate_events,
                           get_slack_log_path, clean_alerts_index):
    rule_description = metadata['rule.description']
    rule_id = metadata['rule.id']
    rule_level = metadata['rule.level']
    extra_srcuser = metadata['extra']['srcuser']
    timestamp_regex = r'\d+-\d+-\d+T\d+:\d+:\d+\.\d+[\+|-]\d+'

    expected_alert_json = fr".+timestamp\":\"({timestamp_regex})\",.+level\":{rule_level}.+description\"" \
                          fr":\"{rule_description}.+id.+{rule_id}.+srcuser.+{extra_srcuser}"

    expected_indexed_alert = fr".+srcuser.+{extra_srcuser}.+level.+{rule_level}.+description.+{rule_description}.+id" \
                             fr".+{rule_id}.+timestamp\": \"({timestamp_regex})\""

    expected_slack_log = fr".*{rule_description}.+{rule_id} _\(Level {rule_level}\)"

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
            "rule.description": f"{rule_description}"
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

    # Check if the alert received in Slack is the same as the triggered one
    evm.check_event(callback=expected_slack_log, file_to_monitor=get_slack_log_path,
                    timeout=fw.T_5, error_message='The alert has not reached Slack').result()
