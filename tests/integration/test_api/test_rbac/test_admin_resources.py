# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
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
    """Test if admin security users can be removed."""
    api_details = get_api_details()

    endpoint = '/security/users'
    resource = 'user_ids'
    admin_ids = get_admin_resources(api_details, endpoint)
    remove_admin_resources(api_details, admin_ids, endpoint, resource, 5004)


def test_admin_roles(restart_api, get_api_details):
    """Test if admin security roles can be removed."""
    api_details = get_api_details()

    endpoint = '/security/roles'
    resource = 'role_ids'
    body = {'name': 'random_role_name_test'}

    admin_ids = get_admin_resources(api_details, endpoint)
    remove_admin_resources(api_details, admin_ids, endpoint, resource, 4008)
    modify_admin_resources(api_details, admin_ids, endpoint, body)


def test_admin_policies(restart_api, get_api_details):
    """Test if admin security policies can be removed."""
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
    api_details = get_api_details()

    endpoint = '/security/rules'
    resource = 'rule_ids'
    body = {'name': 'random_rule_name_test', 'rule': {'rule_key': 'rule_value'}}

    admin_ids = get_admin_resources(api_details, endpoint)
    remove_admin_resources(api_details, admin_ids, endpoint, resource, 4008)
    modify_admin_resources(api_details, admin_ids, endpoint, body)
