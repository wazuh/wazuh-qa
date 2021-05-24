import pytest
import requests

from wazuh_testing.api import get_api_details_dict


@pytest.fixture(scope='function')
def set_security_resources(request):
    def remove_test_security_resources(endpoint):
        parameter = {
            users_endpoint: 'user_ids',
            roles_endpoint: 'role_ids',
            policies_endpoint: 'policy_ids',
            rules_endpoint: 'rule_ids'
        }
        remove = requests.delete(f'{endpoint}?{parameter[endpoint]}=all', headers=api_details['auth_headers'],
                                 verify=False)
        assert remove.status_code == 200, f'Could not clean security resources. Response: {remove.text}'

    api_details = get_api_details_dict()
    users_endpoint = api_details['base_url'] + '/security/users'
    roles_endpoint = api_details['base_url'] + '/security/roles'
    policies_endpoint = api_details['base_url'] + '/security/policies'
    rules_endpoint = api_details['base_url'] + '/security/rules'

    # Create new user
    response = requests.post(users_endpoint,
                             json={'username': f'test_user',
                                   'password': 'Password1!'},
                             headers=api_details['auth_headers'], verify=False)
    assert response.status_code == 200, f'Expected status code was 200. Full response: ' \
                                        f'{response.text}'
    user_id = response.json()['data']['affected_items'][0]['id']

    # Edit allow_run_as
    response = requests.put(users_endpoint + f'/{user_id}/run_as?allow_run_as=true',
                            headers=api_details['auth_headers'], verify=False)
    assert response.status_code == 200, f'Expected status code was 200. Full response: ' \
                                        f'{response.text}'

    # Create new role
    response = requests.post(roles_endpoint,
                             json={'name': f'test_role'},
                             headers=api_details['auth_headers'], verify=False)
    assert response.status_code == 200, f'Expected status code was 200. Full response: ' \
                                        f'{response.text}'
    role_id = response.json()['data']['affected_items'][0]['id']

    # Create new policy
    response = requests.post(policies_endpoint,
                             json={'name': f'test_policy',
                                   'policy': {
                                       'actions': ['agent:read'],
                                       'resources': [f'agent:id:999'],
                                       'effect': 'allow'
                                   }},
                             headers=api_details['auth_headers'], verify=False)
    assert response.status_code == 200, f'Expected status code was 200. Full response: ' \
                                        f'{response.text}'
    policy_id = response.json()['data']['affected_items'][0]['id']

    # Create new rule
    response = requests.post(rules_endpoint,
                             json={'name': f'test_rule',
                                   'rule': {
                                       'FIND$': {
                                           'definition': 'test'
                                       }
                                   }},
                             headers=api_details['auth_headers'], verify=False)
    assert response.status_code == 200, f'Expected status code was 200. Full response: ' \
                                        f'{response.text}'
    rule_id = response.json()['data']['affected_items'][0]['id']

    # Create relationships between them
    # User-Role
    response = requests.post(f"{users_endpoint}/{user_id}/roles?role_ids={role_id}",
                             headers=api_details['auth_headers'], verify=False)
    assert response.status_code == 200, f'Expected status code was 200. Full response: ' \
                                        f'{response.text}'

    # Role-Policy
    response = requests.post(f"{roles_endpoint}/{role_id}/policies?policy_ids={policy_id}",
                             headers=api_details['auth_headers'], verify=False)
    assert response.status_code == 200, f'Expected status code was 200. Full response: ' \
                                        f'{response.text}'

    # Role-Rule
    response = requests.post(f"{roles_endpoint}/{role_id}/rules?rule_ids={rule_id}",
                             headers=api_details['auth_headers'], verify=False)
    assert response.status_code == 200, f'Expected status code was 200. Full response: ' \
                                        f'{response.text}'

    setattr(request.module, 'user_id', user_id)
    setattr(request.module, 'role_id', role_id)
    setattr(request.module, 'policy_id', policy_id)
    setattr(request.module, 'rule_id', rule_id)

    yield

    remove_test_security_resources(users_endpoint)
    remove_test_security_resources(roles_endpoint)
    remove_test_security_resources(policies_endpoint)
    remove_test_security_resources(rules_endpoint)
