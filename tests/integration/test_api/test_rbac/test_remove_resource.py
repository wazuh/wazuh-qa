# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import requests
from wazuh_testing.api import get_security_resource_information

# Variables
user_id, role_id, policy_id, rule_id = None, None, None, None


# Functions
def check_relationships(original_relationships, new_relationships, deleted_relationship):
    """Check if the relationships stay the same after removing security resources.

    Parameters
    ----------
    original_relationships : dict
        Original relationships.
    new_relationships : dict
        Relationships after removing a security resource.
    deleted_relationship : str
        Security resource that was deleted.
    """
    original_relationships[deleted_relationship] = []
    assert original_relationships == new_relationships, f'Some relationships were deleted. ' \
                                                        f'\nOriginal: {original_relationships}\n' \
                                                        f'New: {new_relationships}'


def check_resources(deleted_resource, resource_id):
    """Check if the security resources stay the same.

    Parameters
    ----------
    deleted_resource : str
        Name of the deleted resource.
    resource_id : int
        ID of the resource.
    """
    resources = {
        'users': 'user_ids',
        'roles': 'role_ids',
        'policies': 'policy_ids',
        'rules': 'rule_ids'
    }
    del resources[deleted_resource]
    # Check that the rest of resources still exists
    for param in resources.values():
        assert get_security_resource_information(**{param: resource_id})


# Tests
def test_remove_rule(set_security_resources, get_api_details):
    """Test if relationships between security resources stay the same after removing the linked rule."""
    api_details = get_api_details()
    relationships = get_security_resource_information(role_ids=role_id)
    assert relationships, 'There are not relationships'

    delete_endpoint = api_details['base_url'] + f'/security/rules?rule_ids={rule_id}'
    response = requests.delete(delete_endpoint, headers=api_details['auth_headers'], verify=False)
    assert response.status_code == 200, f'Status code was not 200. Response: {response.text}'

    new_relationships = get_security_resource_information(role_ids=role_id)
    assert new_relationships, 'There are not relationships'

    check_resources('rules', rule_id)
    check_relationships(relationships, new_relationships, 'rules')


def test_remove_policy(set_security_resources, get_api_details):
    """Test if relationships between security resources stay the same after removing the linked policy."""
    api_details = get_api_details()
    relationships = get_security_resource_information(role_ids=role_id)
    assert relationships, 'There are not relationships'

    delete_endpoint = api_details['base_url'] + f'/security/policies?policy_ids={policy_id}'
    response = requests.delete(delete_endpoint, headers=api_details['auth_headers'], verify=False)
    assert response.status_code == 200, f'Status code was not 200. Response: {response.text}'

    new_relationships = get_security_resource_information(role_ids=role_id)
    assert new_relationships, 'There are not relationships'

    check_resources('policies', policy_id)
    check_relationships(relationships, new_relationships, 'policies')


def test_remove_user(set_security_resources, get_api_details):
    """Test if relationships between security resources stay the same after removing the linked user."""
    api_details = get_api_details()
    relationships = get_security_resource_information(role_ids=role_id)
    assert relationships, 'There are not relationships'

    delete_endpoint = api_details['base_url'] + f'/security/users?user_ids={user_id}'
    response = requests.delete(delete_endpoint, headers=api_details['auth_headers'], verify=False)
    assert response.status_code == 200, f'Status code was not 200. Response: {response.text}'

    new_relationships = get_security_resource_information(role_ids=role_id)
    assert new_relationships, 'There are not relationships'

    check_resources('users', user_id)
    check_relationships(relationships, new_relationships, 'users')


def test_remove_role(set_security_resources, get_api_details):
    """Test if relationships between security resources stay the same after removing the linked role."""
    api_details = get_api_details()
    relationships = get_security_resource_information(user_ids=user_id)
    assert relationships, 'There are not relationships'

    delete_endpoint = api_details['base_url'] + f'/security/roles?role_ids={role_id}'
    response = requests.delete(delete_endpoint, headers=api_details['auth_headers'], verify=False)
    assert response.status_code == 200, f'Status code was not 200. Response: {response.text}'

    new_relationships = get_security_resource_information(user_ids=user_id)
    assert new_relationships, 'There are not relationships'

    check_resources('roles', role_id)
    check_relationships(relationships, new_relationships, 'roles')
