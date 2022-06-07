import json
import os
import re
import pytest
import requests
from requests.auth import HTTPBasicAuth

from wazuh_testing.tools import configuration as config

# Test cases data
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases')
test_cases_file_path = os.path.join(TEST_CASES_PATH, 'cases_test_docker_monitoring.json')

# Playbooks
playbooks = {
    'setup_playbooks': ['configuration.yaml', 'generate_alerts.yaml'],
    'teardown_playbooks': [],
    'skip_teardown': True
}

# Configuration
configurations, configuration_metadata, cases_ids = config.get_test_cases_data(test_cases_file_path, format='json')


def get_alerts_from_opensearch_api(user, password, query):
    hostname = 'wazuh-manager'
    params = {'pretty': 'true'}
    headers = {'Content-Type': 'application/json'}
    path = 'wazuh-alerts-4.x-*/_search'
    url = f"https://{hostname}:9200/{path}"
    
    response = requests.get(url=url, params=params, verify=False, auth=HTTPBasicAuth(user, password), json=query,
                            headers=headers)

    assert response.status_code == 200, 'The response is not the expected. ' \
                                        f"Actual: {response.status_code} - {response.content}"

    opensearch_query_result = json.dumps(response.json())

    return opensearch_query_result


@pytest.mark.parametrize('metadata', configuration_metadata, ids=cases_ids)
@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
def test_docker_monitoring(run_ansible_playbooks, metadata, get_opensearch_credentials):
    user, password = get_opensearch_credentials
    opensearch_result = get_alerts_from_opensearch_api(user, password, metadata['opensearch_query'])

    match = re.search(metadata['regex'], opensearch_result)

    assert match is not None, 'The expected alerts were not indexed.'
