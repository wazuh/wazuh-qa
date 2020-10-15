import pytest
import requests

from wazuh_testing.api import get_api_details_dict


@pytest.fixture(scope='module')
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

    user_ids, role_ids, policy_ids, rule_ids = list(), list(), list(), list()

    for i in range(5):
        # Create new user
        response = requests.post(users_endpoint,
                                 json={'username': f'user_{i}',
                                       'password': 'Password1!',
                                       'allow_run_as': False},
                                 headers=api_details['auth_headers'], verify=False)
        assert response.status_code == 200, f'Expected status code was 200. Full response: ' \
                                            f'{response.text}'
        user_ids.append(response.json()['data']['affected_items'][0]['id'])

        # Create new role
        response = requests.post(roles_endpoint,
                                 json={'name': f'role_{i}'},
                                 headers=api_details['auth_headers'], verify=False)
        assert response.status_code == 200, f'Expected status code was 200. Full response: ' \
                                            f'{response.text}'
        role_ids.append(response.json()['data']['affected_items'][0]['id'])

        # Create new policy
        response = requests.post(policies_endpoint,
                                 json={'name': f'policy_{i}',
                                       'policy': {
                                           'actions': ['agent:read'],
                                           'resources': [f'agent:id:{i}'],
                                           'effect': 'allow'
                                       }},
                                 headers=api_details['auth_headers'], verify=False)
        assert response.status_code == 200, f'Expected status code was 200. Full response: ' \
                                            f'{response.text}'
        policy_ids.append(response.json()['data']['affected_items'][0]['id'])

        # Create new rule
        response = requests.post(rules_endpoint,
                                 json={'name': f'rule_{i}',
                                       'rule': {
                                           'FIND$': {
                                               'definition': i
                                           }
                                       }},
                                 headers=api_details['auth_headers'], verify=False)
        assert response.status_code == 200, f'Expected status code was 200. Full response: ' \
                                            f'{response.text}'
        rule_ids.append(response.json()['data']['affected_items'][0]['id'])

        # Create relationships between them
        # User-Role
        response = requests.post(f"{users_endpoint}/{user_ids[-1]}/roles?role_ids={role_ids[-1]}",
                                 headers=api_details['auth_headers'], verify=False)
        assert response.status_code == 200, f'Expected status code was 200. Full response: ' \
                                            f'{response.text}'

        # Role-Policy
        response = requests.post(f"{roles_endpoint}/{role_ids[-1]}/policies?policy_ids={policy_ids[-1]}",
                                 headers=api_details['auth_headers'], verify=False)
        assert response.status_code == 200, f'Expected status code was 200. Full response: ' \
                                            f'{response.text}'

        # Role-Rule
        response = requests.post(f"{roles_endpoint}/{role_ids[-1]}/rules?rule_ids={rule_ids[-1]}",
                                 headers=api_details['auth_headers'], verify=False)
        assert response.status_code == 200, f'Expected status code was 200. Full response: ' \
                                            f'{response.text}'

    setattr(request.module, 'user_ids', user_ids)
    setattr(request.module, 'role_ids', role_ids)
    setattr(request.module, 'policy_ids', policy_ids)
    setattr(request.module, 'rule_ids', rule_ids)

    yield

    remove_test_security_resources(users_endpoint)
    remove_test_security_resources(roles_endpoint)
    remove_test_security_resources(policies_endpoint)
    remove_test_security_resources(rules_endpoint)
