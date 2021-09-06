'''
copyright:
    Copyright (C) 2015-2021, Wazuh Inc.

    Created by Wazuh, Inc. <info@wazuh.com>.

    This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type:
    integration

description:
    These tests will check if the `rbac` (Role-Based Access Control) feature
    of the API is working properly. Specifically, they will verify that
    the different actions that can be performed with admin resources
    are working correctly. The `rbac` capability allows users
    accessing the API to be assigned a role that will define
    the privileges they have.

tiers:
    - 0

component:
    manager

path:
    tests/integration/test_api/test_rbac/

daemons:
    - apid
    - analysisd
    - syscheckd
    - wazuh-db

os_support:
    - linux, centos 6
    - linux, centos 7
    - linux, centos 8
    - linux, rhel6
    - linux, rhel7
    - linux, rhel8
    - linux, amazon linux 1
    - linux, amazon linux 2
    - linux, debian buster
    - linux, debian stretch
    - linux, debian wheezy
    - linux, ubuntu bionic
    - linux, ubuntu xenial
    - linux, ubuntu trusty
    - linux, arch linux

coverage:

pytest_args:

tags:
    - api
'''
import pytest
import requests


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
def test_admin_users(restart_api, get_api_details):
    '''
    description:
        Check if admin security users can be removed. For this purpose,
        it tries to delete these users, expecting an error as a response.

    wazuh_min_version:
        4.1

    parameters:
        - restart_api:
            type: fixture
            brief: Reset `api.log` and start a new monitor.

        - get_api_details:
            type: fixture
            brief: Get API information.

    assertions:
        - Verify that `status code` 200 (ok) is received when collecting the admin security users information.
        - Verify that `status code` 200 (ok) is received when the request to delete the admin security users is made.
        - Verify that the `affected_items` field from the response is empty
          when trying to delete the admin security users.
        - Verify that the `failed_items` array from the response has a size `1`
          when trying to delete the admin security users.
        - Verify that the `failed_items[0]` error code from the response has the value: `5004`
          when trying to delete the admin security users.

    test_input:
        From the `get_admin_resources` function information is obtained to perform the test,
        concretely the `admin_ids`.

    logging:
        - api.log:
            - Requests made to the API should be logged.

    tags:
        - rbac
    '''
    api_details = get_api_details()

    endpoint = '/security/users'
    resource = 'user_ids'
    admin_ids = get_admin_resources(api_details, endpoint)
    remove_admin_resources(api_details, admin_ids, endpoint, resource, 5004)


def test_admin_roles(restart_api, get_api_details):
    '''
    description:
        Check if admin security roles can be removed. For this purpose,
        it tries to delete these roles, expecting an error as a response.

    wazuh_min_version:
        4.1

    parameters:
        - restart_api:
            type: fixture
            brief: Reset `api.log` and start a new monitor.

        - get_api_details:
            type: fixture
            brief: Get API information.

    assertions:
        - Verify that `status code` 200 (ok) is received when collecting the admin security roles information.
        - Verify that `status code` 200 (ok) is received when the request
          to delete or modify the admin security roles is made.
        - Verify that the `affected_items` field from the response is empty
          when trying to delete or modify the admin security roles.
        - Verify that the `failed_items` array from the response has a size `1`
          when trying to delete or modify the admin security roles.
        - Verify that the `failed_items[0]` error code from the response has the value: `4008`
          when trying to delete or modify the admin security roles.

    test_input:
        From the `get_admin_resources` function information is obtained to perform the test,
        concretely the `role_ids`.

    logging:
        - api.log:
            - Requests made to the API should be logged.

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


def test_admin_policies(restart_api, get_api_details):
    '''
    description:
        Check if admin security policies can be removed. For this purpose,
        it tries to delete these policies, expecting an error as a response.

    wazuh_min_version:
        4.1

    parameters:
        - restart_api:
            type: fixture
            brief: Reset `api.log` and start a new monitor.

        - get_api_details:
            type: fixture
            brief: Get API information.

    assertions:
        - Verify that `status code` 200 (ok) is received when collecting the admin security policies information.
        - Verify that `status code` 200 (ok) is received when the request
          to delete or modify the admin security policies is made.
        - Verify that the `affected_items` field from the response is empty
          when trying to delete or modify the admin security policies.
        - Verify that the `failed_items` array from the response has a size `1`
          when trying to delete or modify the admin security policies.
        - Verify that the `failed_items[0]` error code from the response has the value: `4008`
          when trying to delete or modify the admin security policies.

    test_input:
        From the `get_admin_resources` function information is obtained to perform the test,
        concretely the `role_ids`.

    logging:
        - api.log:
            - Requests made to the API should be logged.

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


def test_admin_rules(restart_api, get_api_details):
    """Test if admin security rules can be removed."""
    '''
    description:
        Check if admin security rules can be removed. For this purpose,
        it tries to delete these rules, expecting an error as a response.

    wazuh_min_version:
        4.1

    parameters:
        - restart_api:
            type: fixture
            brief: Reset `api.log` and start a new monitor.

        - get_api_details:
            type: fixture
            brief: Get API information.

    assertions:
        - Verify that `status code` 200 (ok) is received when collecting the admin security rules information.
        - Verify that `status code` 200 (ok) is received when the request
          to delete or modify the admin security rules is made.
        - Verify that the `affected_items` field from the response is empty
          when trying to delete or modify the admin security rules.
        - Verify that the `failed_items` array from the response has a size `1`
          when trying to delete or modify the admin security rules.
        - Verify that the `failed_items[0]` error code from the response has the value: `4008`
          when trying to delete or modify the admin security rules.

    test_input:
        From the `get_admin_resources` function information is obtained to perform the test,
        concretely the `role_ids`.

    logging:
        - api.log:
            - Requests made to the API should be logged.

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
