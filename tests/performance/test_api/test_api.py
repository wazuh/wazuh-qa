from json import dumps
from os.path import join, dirname, realpath
from time import sleep

import pytest
import requests
from yaml import safe_load

test_data = safe_load(open(join(dirname(realpath(__file__)), 'data', 'configuration.yaml')))
configuration = test_data['configuration']
api_details = dict()


# Tests
@pytest.mark.parametrize('test_configuration', [configuration])
@pytest.mark.parametrize('test_case', test_data['test_cases'])
def test_api_endpoints(test_case, test_configuration, set_api_test_environment):
    """Make an API request for each `test_case`. `test_configuration` fixture is only used to add metadata to the
    HTML report."""
    base_url = api_details['base_url']
    headers = api_details['auth_headers']
    response = getattr(requests, test_case['method'])(f"{base_url}{test_case['endpoint']}", headers=headers,
                                                      params=test_case['parameters'], json=test_case['body'],
                                                      verify=False)

    # Add useful information to report as stdout
    print(f'Request elapsed time: {response.elapsed.total_seconds():.3f}s\n')
    print(f'Status code: {response.status_code}\n')
    print(f'Full response:\n{dumps(response.json(), indent=2)}')

    assert response.status_code == 200
    test_case['method'] == 'put' and test_case['restart'] and sleep(configuration['restart_delay'])
