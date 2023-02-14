'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check if the 'RBAC' (Role-Based Access Control) feature of the API is working properly.
       Specifically, they will verify that when resources are added with the same identifier of previously
       existing ones, the previous relationships are not maintained. The 'RBAC' capability allows users
       accessing the API to be assigned a role that will define the privileges they have.

components:
    - api

suite: rbac

targets:
    - manager

daemons:
    - wazuh-apid
    - wazuh-analysisd
    - wazuh-syscheckd
    - wazuh-db

os_platform:
    - linux

os_version:
    - Arch Linux
    - Amazon Linux 2
    - Amazon Linux 1
    - CentOS 8
    - CentOS 7
    - Debian Buster
    - Red Hat 8
    - Ubuntu Focal
    - Ubuntu Bionic

references:
    - https://documentation.wazuh.com/current/user-manual/api/getting-started.html
    - https://documentation.wazuh.com/current/user-manual/api/reference.html#tag/Security
    - https://en.wikipedia.org/wiki/Role-based_access_control

tags:
    - api
'''
import requests
import pytest
from wazuh_testing.api import get_security_resource_information

# Marks
pytestmark = [pytest.mark.server]

# Variables
user_id, role_id, policy_id, rule_id = None, None, None, None


# Tests
@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
def test_add_old_user(restart_api_module, wait_for_start_module, set_security_resources, get_api_details):
    '''
    description: Check if the security relationships of a previous user are maintained
                 in the system after adding a new user with the same ID.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - set_security_resources:
            type: fixture
            brief: Creates a set of security relationships along with a user for testing.
        - get_api_details:
            type: fixture
            brief: Get API information.

    assertions:
        - Verify that the testing user information exists.
        - Verify that the request to remove the testing agent is successfully processed.
        - Verify that the request to add the testing agent is successfully processed.
        - Verify that security relationships do not exist between the old and the new user.

    inputs:
        - The testing 'user_id' as a module attribute.

    input_description: From the 'set_security_resources' fixture information is obtained to perform
                       the test, concretely the 'user_id'.

    expected_output:
        - A 'JSON' string in the response body with information of the old user.
        - r'200' ('OK' HTTP status code at deleting the old user)
        - r'200' ('OK' HTTP status code at inserting the old user)

    tags:
        - rbac
    '''
    api_details = get_api_details()
    old_user_info = get_security_resource_information(user_ids=user_id)
    assert old_user_info, f'There is not information about this role: {user_id}'

    delete_endpoint = api_details['base_url'] + f'/security/users?user_ids={user_id}'
    response = requests.delete(delete_endpoint, headers=api_details['auth_headers'], verify=False)
    assert response.status_code == 200, f'Status code was not 200. Response: {response.text}'

    add_endpoint = api_details['base_url'] + f'/security/users'
    response = requests.post(add_endpoint, json={'username': old_user_info['username'],
                                                 'password': 'Password1!'}, headers=api_details['auth_headers'],
                             verify=False)
    assert response.status_code == 200, f'Status code was not 200. Response: {response.text}'
    relationships = response.json()['data']['affected_items'][0]
    for key, value in relationships.items():
        if key not in ['id', 'username', 'password', 'allow_run_as']:
            assert not value, f'Relationships are not empty: {key}->{value}'


@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
def test_add_old_role(set_security_resources, get_api_details):
    '''
    description: Check if the security relationships of a previous role are maintained
                 in the system after adding a new role with the same ID.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - set_security_resources:
            type: fixture
            brief: Creates a set of security relationships along with a user for testing.
        - get_api_details:
            type: fixture
            brief: Get API information.

    assertions:
        - Verify that the testing role information exists.
        - Verify that the request to remove the testing role is successfully processed.
        - Verify that the request to add the testing role is successfully processed.
        - Verify that security relationships do not exist between the old and the new role.

    inputs:
        - The testing 'role_id' as a module attribute.

    input_description: From the 'set_security_resources' fixture information is obtained
                       to perform the test, concretely the 'role_id'.

    expected_output:
        - A 'JSON' string in the response body with information of the old role.
        - r'200' ('OK' HTTP status code at deleting the old role)
        - r'200' ('OK' HTTP status code at inserting the old role)

    tags:
        - rbac
    '''
    api_details = get_api_details()
    old_role_info = get_security_resource_information(role_ids=role_id)
    assert old_role_info, f'There is not information about this role: {role_id}'

    delete_endpoint = api_details['base_url'] + f'/security/roles?role_ids={role_id}'
    response = requests.delete(delete_endpoint, headers=api_details['auth_headers'], verify=False)
    assert response.status_code == 200, f'Status code was not 200. Response: {response.text}'

    add_endpoint = api_details['base_url'] + f'/security/roles'
    response = requests.post(add_endpoint, json={'name': old_role_info['name']}, headers=api_details['auth_headers'],
                             verify=False)
    assert response.status_code == 200, f'Status code was not 200. Response: {response.text}'
    relationships = response.json()['data']['affected_items'][0]
    for key, value in relationships.items():
        if key not in ['id', 'name']:
            assert not value, f'Relationships are not empty: {key}->{value}'


@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
def test_add_old_policy(set_security_resources, get_api_details):
    '''
    description: Check if the security relationships of a previous policy are maintained
                 in the system after adding a new policy with the same ID.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - set_security_resources:
            type: fixture
            brief: Creates a set of security relationships along with a user for testing.
        - get_api_details:
            type: fixture
            brief: Get API information.

    assertions:
        - Verify that the testing policy information exists.
        - Verify that the request to remove the testing policy is successfully processed.
        - Verify that the request to add the testing policy is successfully processed.
        - Verify that security relationships do not exist between the old and the new policy.

    inputs:
        - The testing 'policy_id' as a module attribute.

    input_description: From the 'set_security_resources' fixture information is obtained to perform the test,
                       concretely the 'policy_id'.

    expected_output:
        - A 'JSON' string in the response body with information of the old policy.
        - r'200' ('OK' HTTP status code at deleting the old policy)
        - r'200' ('OK' HTTP status code at inserting the old policy)

    tags:
        - rbac
    '''
    api_details = get_api_details()
    old_policy_info = get_security_resource_information(policy_ids=policy_id)
    assert old_policy_info, f'There is not information about this policy: {policy_id}'

    delete_endpoint = api_details['base_url'] + f'/security/policies?policy_ids={policy_id}'
    response = requests.delete(delete_endpoint, headers=api_details['auth_headers'], verify=False)
    assert response.status_code == 200, f'Status code was not 200. Response: {response.text}'

    add_endpoint = api_details['base_url'] + f'/security/policies'
    response = requests.post(add_endpoint,
                             json={'name': old_policy_info['name'],
                                   'policy': old_policy_info['policy']},
                             headers=api_details['auth_headers'],
                             verify=False)
    assert response.status_code == 200, f'Status code was not 200. Response: {response.text}'
    relationships = response.json()['data']['affected_items'][0]
    for key, value in relationships.items():
        if key not in ['id', 'name', 'policy']:
            assert not value, f'Relationships are not empty: {key}->{value}'


@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
def test_add_old_rule(set_security_resources, get_api_details):
    '''
    description: Check if the security relationships of a previous rule are maintained
                 in the system after adding a new rule with the same ID.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - set_security_resources:
            type: fixture
            brief: Creates a set of security relationships along with a user for testing.
        - get_api_details:
            type: fixture
            brief: Get API information.

    assertions:
        - Verify that the testing rule information exists.
        - Verify that the request to remove the testing rule is successfully processed.
        - Verify that the request to add the testing rule is successfully processed.
        - Verify that security relationships do not exist between the old and the new rule.

    inputs:
        - The testing 'rule_id' as a module attribute.

    input_description: From the 'set_security_resources' fixture information is obtained
                       to perform the test, concretely the 'rule_id'.

    expected_output:
        - A 'JSON' string in the response body with information of the old rule.
        - r'200' ('OK' HTTP status code at deleting the old rule)
        - r'200' ('OK' HTTP status code at inserting the old rule)

    tags:
        - rbac
    '''
    api_details = get_api_details()
    old_rule_info = get_security_resource_information(rule_ids=rule_id)
    assert old_rule_info, f'There is not information about this policy: {rule_id}'

    delete_endpoint = api_details['base_url'] + f'/security/rules?rule_ids={rule_id}'
    response = requests.delete(delete_endpoint, headers=api_details['auth_headers'], verify=False)
    assert response.status_code == 200, f'Status code was not 200. Response: {response.text}'

    add_endpoint = api_details['base_url'] + f'/security/rules'
    response = requests.post(add_endpoint,
                             json={'name': old_rule_info['name'],
                                   'rule': old_rule_info['rule']},
                             headers=api_details['auth_headers'],
                             verify=False)
    assert response.status_code == 200, f'Status code was not 200. Response: {response.text}'
    relationships = response.json()['data']['affected_items'][0]
    for key, value in relationships.items():
        if key not in ['id', 'name', 'rule']:
            assert not value, f'Relationships are not empty: {key}->{value}'
