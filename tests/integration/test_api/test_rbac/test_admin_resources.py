'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check if the 'RBAC' (Role-Based Access Control) feature of the API is working properly.
       Specifically, they will verify that the different actions that can be performed with admin resources
       are working correctly. The 'RBAC' capability allows users accessing the API to be assigned a role
       that will define the privileges they have.

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
import pytest
import requests

# Marks
pytestmark = [pytest.mark.server]


@pytest.fixture(scope='module')
def get_configuration():
    # Needed to restart the API
    pass


# Functions
def get_admin_resources(api_details, endpoint):
    response = requests.get(f"{api_details['base_url']}{endpoint}", headers=api_details['auth_headers'], verify=False)
    assert response.status_code == 200, f'Expected status code was 200. Full response: {response.text}'

    admin_ids = [item['id'] for item in response.json()['data']['affected_items'] if item['id'] < 100]

    return admin_ids


def remove_admin_resources(api_details, admin_ids, endpoint, resource, exception):
    """Try to remove all admin security resources and expect the proper exception.

    Parameters
    ----------
    api_details : dict
        API details.
    admin_ids : list
        List of admin IDs.
    endpoint : str
        Security endpoint.
    resource : str
        Name of the resources.
    exception : int
        Expected exception code.
    """
    response = requests.delete(
        f"{api_details['base_url']}{endpoint}?{resource}={','.join([str(id) for id in admin_ids])}",
        headers=api_details['auth_headers'], verify=False)
    assert response.status_code == 200, f'Expected status code was 200. Full response: {response.text}'
    data = response.json()['data']
    assert not data['affected_items'], f"Admin resources could be deleted: {data['affected_items']}"
    assert len(data['failed_items']) == 1, f'Expected one failed item'
    assert data['failed_items'][0]['error']['code'] == exception, 'Error code was different from expected: ' \
                                                                  f"{data['failed_items'][0]['error']['code']}"
    assert admin_ids == data['failed_items'][0]['id'], f"IDs do not match: {data['failed_items'][0]['id']}"


def modify_admin_resources(api_details, admin_ids, endpoint, body):
    """Try to remove all admin security resources and expect the proper exception.

    Parameters
    ----------
    api_details : dict
        API details.
    admin_ids : list
        List of admin IDs.
    endpoint : str
        Security endpoint.
    body : dict
        Dictionary with the security resource information to be changed.
    """
    for resource_id in admin_ids:
        response = requests.put(f"{api_details['base_url']}{endpoint}/{resource_id}", json=body,
                                headers=api_details['auth_headers'], verify=False)
        assert response.status_code == 200, f'Expected status code was 200. Full response: {response.text}'
        data = response.json()['data']
        assert not data['affected_items'], f"Admin resources could be modified: {data['affected_items']}"
        assert len(data['failed_items']) == 1, f'Expected one failed item'
        assert data['failed_items'][0]['error']['code'] == 4008, 'Error code was different from expected: ' \
                                                                 f"{data['failed_items'][0]['error']['code']}"
        assert [resource_id] == data['failed_items'][0]['id'], f"ID does not match: {data['failed_items'][0]['id']}"


# Tests
@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
def test_admin_users(restart_api, wait_for_start, get_api_details):
    '''
    description: Check if the admin security users can be removed. For this purpose,
                 it tries to delete these users, expecting an error as a response.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - restart_api:
            type: fixture
            brief: Reset 'api.log' and start a new monitor.
        - get_api_details:
            type: fixture
            brief: Get API information.

    assertions:
        - Verify that the request to collect the admin security users information is done correctly.
        - Verify that the request to delete the admin security users is done correctly.
        - Verify that admin security users have not been deleted by checking the response of the request.

    inputs:
        - The data are obtained from within the test.

    input_description: From the 'get_admin_resources' function information is obtained to perform
                       the test, concretely the 'admin_ids'.

    expected_output:
        - r'200' ('OK' HTTP status code at collect the admin security users information)
        - r'200' ('OK' HTTP status code when trying to delete the admin security users)
        - r'1' (Size of the 'failed_items' array from the response body)
        - r'5004' (Error code of the 'failed_items[0]' array from the response body)

    tags:
        - rbac
    '''
    api_details = get_api_details()

    endpoint = '/security/users'
    resource = 'user_ids'
    admin_ids = get_admin_resources(api_details, endpoint)
    remove_admin_resources(api_details, admin_ids, endpoint, resource, 5004)


@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
def test_admin_roles(restart_api, wait_for_start, get_api_details):
    '''
    description: Check if the admin security roles can be removed. For this purpose,
                 it tries to delete these roles, expecting an error as a response.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - restart_api:
            type: fixture
            brief: Reset 'api.log' and start a new monitor.
        - get_api_details:
            type: fixture
            brief: Get API information.

    assertions:
        - Verify that the request to collect the admin security roles information is done correctly.
        - Verify that the request to delete the admin security roles is done correctly.
        - Verify that admin security roles have not been deleted by checking the response of the request.

    inputs:
        - The data are obtained from within the test.

    input_description: From the 'get_admin_resources' function information is obtained
                       to perform the test, concretely the 'role_ids'.

    expected_output:
        - r'200' ('OK' HTTP status code at collect the admin security roles information)
        - r'200' ('OK' HTTP status code when trying to delete the admin security roles)
        - r'1' (Size of the 'failed_items' array from the response body)
        - r'4008' (Error code of the 'failed_items[0]' array from the response body)

    tags:
        - rbac
    '''
    api_details = get_api_details()

    endpoint = '/security/roles'
    resource = 'role_ids'
    body = {'name': 'random_role_name_test'}

    admin_ids = get_admin_resources(api_details, endpoint)
    remove_admin_resources(api_details, admin_ids, endpoint, resource, 4008)
    modify_admin_resources(api_details, admin_ids, endpoint, body)


@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
def test_admin_policies(restart_api, wait_for_start, get_api_details):
    '''
    description: Check if the admin security policies can be removed. For this purpose,
                 it tries to delete these policies, expecting an error as a response.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - restart_api:
            type: fixture
            brief: Reset 'api.log' and start a new monitor.
        - get_api_details:
            type: fixture
            brief: Get API information.

    assertions:
        - Verify that the request to collect the admin security policies information is done correctly.
        - Verify that the request to delete the admin security policies is done correctly.
        - Verify that admin security policies have not been deleted by checking the response of the request.

    inputs:
        - The data are obtained from within the test.

    input_description: From the 'get_admin_resources' function information is obtained
                       to perform the test, concretely the 'policy_ids'.

    expected_output:
        - r'200' ('OK' HTTP status code at collect the admin security policies information)
        - r'200' ('OK' HTTP status code when trying to delete the admin security policies)
        - r'1' (Size of the 'failed_items' array from the response body)
        - r'4008' (Error code of the 'failed_items[0]' array from the response body)

    tags:
        - rbac
    '''
    api_details = get_api_details()

    endpoint = '/security/policies'
    resource = 'policy_ids'
    body = {'name': 'random_policy_name_test',
            'policy': {'actions': ['test_action'], 'resources': ['test_resources'], 'effect': 'allow'}}

    admin_ids = get_admin_resources(api_details, endpoint)
    remove_admin_resources(api_details, admin_ids, endpoint, resource, 4008)
    modify_admin_resources(api_details, admin_ids, endpoint, body)


@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
def test_admin_rules(restart_api, wait_for_start, get_api_details):
    '''
    description: Check if the admin security rules can be removed. For this purpose,
                 it tries to delete these rules, expecting an error as a response.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - restart_api:
            type: fixture
            brief: Reset 'api.log' and start a new monitor.
        - get_api_details:
            type: fixture
            brief: Get API information.

    assertions:
        - Verify that the request to collect the admin security rules information is done correctly.
        - Verify that the request to delete the admin security rules is done correctly.
        - Verify that admin security rules have not been deleted by checking the response of the request.

    inputs:
        - The data are obtained from within the test.

    input_description: From the 'get_admin_resources' function information is obtained
                       to perform the test, concretely the 'rule_ids'.

    expected_output:
        - r'200' ('OK' HTTP status code at collect the admin security rules information)
        - r'200' ('OK' HTTP status code when trying to delete the admin security rules)
        - r'1' (Size of the 'failed_items' array from the response body)
        - r'4008' (Error code of the 'failed_items[0]' array from the response body)

    tags:
        - rbac
    '''
    api_details = get_api_details()

    endpoint = '/security/rules'
    resource = 'rule_ids'
    body = {'name': 'random_rule_name_test', 'rule': {'rule_key': 'rule_value'}}

    admin_ids = get_admin_resources(api_details, endpoint)
    remove_admin_resources(api_details, admin_ids, endpoint, resource, 4008)
    modify_admin_resources(api_details, admin_ids, endpoint, body)
