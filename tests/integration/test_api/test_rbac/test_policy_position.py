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
    that the policies are applied to the roles in the right order.
    The `rbac` capability allows users accessing the API to be assigned
    a role that will define the privileges they have.

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
from wazuh_testing.api import get_security_resource_information

# Variables
user_id, role_id, policy_id, rule_id = None, None, None, None
policy_positions = list()


@pytest.fixture(scope='function')
def add_new_policies(get_api_details):
    """Create new policies and relationships between them and the testing role."""
    api_details = get_api_details()
    # Add first policy to list
    policy_positions.append(policy_id)
    for position in range(1, 4):
        # Create new policy
        response = requests.post(api_details['base_url'] + '/security/policies',
                                 json={'name': f'test_policy_position_{position}',
                                       'policy': {
                                           'actions': ['agent:read'],
                                           'resources': [f'agent:id:{position}'],
                                           'effect': 'allow'
                                       }},
                                 headers=api_details['auth_headers'], verify=False)
        assert response.status_code == 200, 'Expected status code was 200. Full response: ' \
                                            f'{response.text}'
        p_id = response.json()['data']['affected_items'][0]['id']

        # Create Role-Policy
        response = requests.post(f"{api_details['base_url']}/security/roles/{role_id}/policies?policy_ids={p_id}"
                                 f"&position={position}",
                                 headers=api_details['auth_headers'], verify=False)
        assert response.status_code == 200, 'Expected status code was 200. Full response: ' \
                                            f'{response.text}'
        policy_positions.insert(position, p_id)


# Functions
def remove_role_policy(api_details, p_id):
    """Remove a role-policy relationship and update the relationships reference list.

    Parameters
    ----------
    p_id : int
        Policy ID.
    """
    response = requests.delete(f"{api_details['base_url']}/security/roles/{role_id}/policies?policy_ids={p_id}",
                               headers=api_details['auth_headers'], verify=False)
    assert response.status_code == 200, f'Expected status code was 200. Full response: {response.text}'
    policy_positions.remove(p_id)
    assert get_security_resource_information(role_ids=role_id)['policies'] == policy_positions, 'Positions do not match'


def add_role_policy(api_details, p_id, position):
    """Add a role-policy relationship and update the relationships reference list.

    Parameters
    ----------
    p_id : int
        Policy ID.
    position : int
        Relationship position.
    """
    response = requests.post(f"{api_details['base_url']}/security/roles/{role_id}/policies?policy_ids={p_id}"
                             f"&position={position}", headers=api_details['auth_headers'], verify=False)
    assert response.status_code == 200, f'Expected status code was 200. Full response: {response.text}'
    policy_positions.insert(position, p_id)
    assert get_security_resource_information(role_ids=role_id)['policies'] == policy_positions, 'Positions do not match'


# Tests
def test_policy_position(set_security_resources, add_new_policies, get_api_details):
    '''
    description:
        Check if the correct order between role-policy relationships remain after
        removing some of them and adding others using the `position` parameter.

    wazuh_min_version:
        4.1

    parameters:
        - set_security_resources:
            type: fixture
            brief: Creates a set of role-based security resources along with a user for testing.

        - add_new_policies:
            type: fixture
            brief: Create new policies and relationships between them and the testing role.

        - get_api_details:
            type: fixture
            brief: Get API information.

    assertions:
        - Verify that `status code` 200 (ok) is received when to remove or add a role-policy.
        - Verify that the role-policy positions are kept in order when deleting or adding a role-policy.

    test_input:
        From the `add_new_policies`, `remove_role_policy` and `add_role_policy` fixtures information
        is obtained to perform the test, concretely the `policy_ids` array.

    logging:
        - api.log:
            - Requests made to the API should be logged.

    tags:
        - rbac
    '''
    api_details = get_api_details()

    # Remove and add in the same position
    pol_id = policy_positions[2]
    remove_role_policy(api_details, pol_id)
    add_role_policy(api_details, pol_id, 2)

    # Remove and add in different positions
    pol_id = policy_positions[3]
    remove_role_policy(api_details, pol_id)
    add_role_policy(api_details, pol_id, 0)

    # Remove and add in the same position after changing the initial state
    pol_id = policy_positions[1]
    remove_role_policy(api_details, pol_id)
    add_role_policy(api_details, pol_id, 1)
