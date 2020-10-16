# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import requests
from wazuh_testing.api import get_security_resource_information

# Variables
user_id, role_id, policy_id, rule_id = None, None, None, None


# Tests
def test_add_old_user(set_security_resources, get_api_details):
    """Remove a user with defined relationships and create it with the same ID to see if said relationships remain."""
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


def test_add_old_role(set_security_resources, get_api_details):
    """Remove a role with defined relationships and create it with the same ID to see if said relationships remain."""
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


def test_add_old_policy(set_security_resources, get_api_details):
    """Remove a policy with defined relationships and create it with the same ID to see if said relationships remain."""
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


def test_add_old_rule(set_security_resources, get_api_details):
    """Remove a rule with defined relationships and create it with the same ID to see if said relationships remain."""
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
