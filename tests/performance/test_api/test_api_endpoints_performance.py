from json import dumps
from os.path import join, dirname, realpath
from time import sleep

import warnings
import pytest
import requests
from yaml import safe_load

restart_delay = safe_load(open(join(dirname(realpath(__file__)), 'data', 'configuration.yaml'))
                          )['configuration']['restart_delay']
test_data = safe_load(open(join(dirname(realpath(__file__)), 'data', 'wazuh_api_endpoints_performance.yaml')))
case_ids = [f"{case['method']}_{case['endpoint']}" for case in test_data['test_cases']]
api_details = dict()

xfailed_items = {
    '/agents/group': {'message': 'Investigate performance issues with PUT /agents/group API endpoint: '
                                 'https://github.com/wazuh/wazuh/issues/13872',
                      'method': 'put'},
    '/active-response': {'message': 'Investigate invalid commands with PUT /active-response endpoint: '
                                    'https://github.com/wazuh/wazuh-qa/issues/5648',
                         'method': 'put'}
}


# Tests
@pytest.mark.parametrize('test_case', test_data['test_cases'], ids=case_ids)
def test_api_endpoints(test_case, set_api_test_environment, api_healthcheck):
    """Make an API request for each `test_case`.

    Args:
        test_case (dict): Dictionary with the endpoint to be tested and the necessary parameters for the test.
        set_api_test_environment (fixture): Fixture that modifies the API security options.
        api_healthcheck (fixture): Fixture used to check that the API is ready to respond requests.
    """
    base_url = api_details['base_url']
    headers = api_details['auth_headers']
    response = None

    try:
        response = getattr(requests, test_case['method'])(f"{base_url}{test_case['endpoint']}", headers=headers,
                                                          params=test_case['parameters'], json=test_case['body'],
                                                          verify=False)
        assert response.status_code == 200
        assert response.json()['error'] == 0

    except AssertionError as e:
        # If the assertion fails, and is marked as xfail
        if test_case['endpoint'] in xfailed_items.keys() and \
                test_case['method'] == xfailed_items[test_case['endpoint']]['method']:
            pytest.xfail(xfailed_items[test_case['endpoint']]['message'])

        raise e

    else:
        # If the test does not fail and is marked as xfail, issue a warning
        if test_case['endpoint'] in xfailed_items.keys() and \
                test_case['method'] == xfailed_items[test_case['endpoint']]['method']:
            warnings.warn(f"Test {test_case['endpoint']} should have failed due "
                          f"to {xfailed_items[test_case['endpoint']]['message']}")

    finally:
        # Add useful information to report as stdout
        try:
            print(f'Request elapsed time: {response.elapsed.total_seconds():.3f}s\n')
            print(f'Status code: {response.status_code}\n')
            print(f'Full response: \n{dumps(response.json(), indent=2)}')
        except KeyError:
            print('No response available')

        # Restart logic as before
        if test_case['method'] == 'put' and test_case['restart']:
            sleep(restart_delay)
