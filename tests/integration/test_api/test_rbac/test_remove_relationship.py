# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import requests

# Variables
from wazuh_testing.api import get_security_resource_information

user_ids, role_ids, policy_ids, rule_ids = list(), list(), list(), list()


# Configurations

def test_remove_user_role_relationship(set_security_resources, get_api_details):
    api_details = get_api_details()

    remove_endpoint = api_details['base_url'] + f'/security/users/{user_ids[0]}/roles?role_ids={role_ids[0]}'
    assert get_security_resource_information(role_ids=role_ids[0])['users'], f'Role {role_ids[0]} does not belong to ' \
                                                                             f'any user'

    # Remove relationship between
    response = requests.delete(remove_endpoint, headers=api_details['auth_headers'], verify=False)
    assert response.status_code == 200, f'Status code was not 200. Response: {response.text}'
    role = get_security_resource_information(role_ids=role_ids[0])

    # Assert resources still exist but the relationship does not
    assert role, 'Role was removed as well'
    assert not role['users'], f'Relationship still exists'
    assert get_security_resource_information(user_ids=user_ids[0]), 'Related user was removed as well'
