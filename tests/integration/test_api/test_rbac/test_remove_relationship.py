# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import requests
from wazuh_testing.api import get_security_resource_information

# Variables
user_ids, role_ids, policy_ids, rule_ids = list(), list(), list(), list()


# Functions
def remove_relationship(api_details, endpoint, resource, related_resource, relation):
    """Remove a relationship between two security resources and check if the resources were deleted.

    Parameters
    ----------
    api_details : dict
        API details such as the headers.
    endpoint : str
        Request endpoint.
    resource : int
        Resource ID.
    related_resource : dict
        Dict with resource information (parameter and ID).
    relation : str
        Role entry of the related resource.
    """
    # Assert the relationship exists
    assert get_security_resource_information(role_ids=resource)[relation], f'Resource {resource} does not belong to ' \
                                                                           f'any {relation}'

    # Remove relationship between
    response = requests.delete(endpoint, headers=api_details['auth_headers'], verify=False)
    assert response.status_code == 200, f'Status code was not 200. Response: {response.text}'
    res = get_security_resource_information(role_ids=resource)

    # Assert resources still exist but the relationship does not
    assert res, 'Resource was removed as well'
    assert not res[relation], f'Relationship still exists'
    assert get_security_resource_information(**related_resource), 'Related user was removed as well'


# Tests
def test_remove_user_role_relationship(set_security_resources, get_api_details):
    """Test if the user and role still exist after removing their relationship."""
    api_details = get_api_details()
    endpoint = api_details['base_url'] + f'/security/users/{user_ids[0]}/roles?role_ids={role_ids[0]}'
    resource = role_ids[0]
    related_resource = {'user_ids': user_ids[0]}
    relation = 'users'

    remove_relationship(api_details, endpoint, resource, related_resource, relation)


def test_remove_role_policy_relationship(set_security_resources, get_api_details):
    """Test if the role and policy still exist after removing their relationship."""
    api_details = get_api_details()
    endpoint = api_details['base_url'] + f'/security/roles/{role_ids[1]}/policies?policy_ids={policy_ids[1]}'
    resource = role_ids[1]
    related_resource = {'policy_ids': policy_ids[1]}
    relation = 'policies'

    remove_relationship(api_details, endpoint, resource, related_resource, relation)


def test_remove_role_rule_relationship(set_security_resources, get_api_details):
    """Test if the role and rule still exist after removing their relationship."""
    api_details = get_api_details()
    endpoint = api_details['base_url'] + f'/security/roles/{role_ids[2]}/rules?rule_ids={rule_ids[2]}'
    resource = role_ids[2]
    related_resource = {'rule_ids': rule_ids[2]}
    relation = 'rules'

    remove_relationship(api_details, endpoint, resource, related_resource, relation)
