'''
copyright:
    Copyright (C) 2015-2021, Wazuh Inc.

    Created by Wazuh, Inc. <info@wazuh.com>.

    This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type:
    integration

description:
    These tests will check if the `rbac` (Role-Based Access Control) feature of the API
    is working properly. Specifically, they will verify that the different relationships
    between users-roles-policies can be correctly removed. 
    The `rbac` capability allows users accessing the API to be assigned a role that
    will define the privileges they have.

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
import requests
from wazuh_testing.api import get_security_resource_information

# Variables
user_id, role_id, policy_id, rule_id = None, None, None, None


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
    '''
    description:
        Check if the user and role still exist after removing their relationship.

    wazuh_min_version:
        4.1

    parameters:
        - set_security_resources:
            type: fixture
            brief: Creates a set of role-based security resources along with a user for testing.

        - get_api_details:
            type: fixture
            brief: Get API information.

    assertions:
        - Verify that the user-role relationship exists.
        - Verify that `status code` 200 (ok) is received when to remove the relationship.
        - Verify that the user-role relationship is removed.
        - Verify that the user and role still exists.

    test_input:
        From the `set_security_resources` fixture information is obtained to perform the test,
        concretely the `user_id` and `role_id`.

    logging:
        - api.log:
            - Requests made to the API should be logged.

    tags:
        - rbac
    '''
    api_details = get_api_details()
    endpoint = api_details['base_url'] + f'/security/users/{user_id}/roles?role_ids={role_id}'
    resource = role_id
    related_resource = {'user_ids': user_id}
    relation = 'users'

    remove_relationship(api_details, endpoint, resource, related_resource, relation)


def test_remove_role_policy_relationship(set_security_resources, get_api_details):
    '''
    description:
        Check if the role and policy still exist after removing their relationship.

    wazuh_min_version:
        4.1

    parameters:
        - set_security_resources:
            type: fixture
            brief: Creates a set of role-based security resources along with a user for testing.

        - get_api_details:
            type: fixture
            brief: Get API information.

    assertions:
        - Verify that the role-policy relationship exists.
        - Verify that `status code` 200 (ok) is received when to remove the relationship.
        - Verify that the role-policy relationship is removed.
        - Verify that the role and policy still exists.

    test_input:
        From the `set_security_resources` fixture information is obtained to perform the test,
        concretely the `role_id` and `policy_id`.

    logging:
        - api.log:
            - Requests made to the API should be logged.

    tags:
        - rbac
    '''
    api_details = get_api_details()
    endpoint = api_details['base_url'] + f'/security/roles/{role_id}/policies?policy_ids={policy_id}'
    resource = role_id
    related_resource = {'policy_ids': policy_id}
    relation = 'policies'

    remove_relationship(api_details, endpoint, resource, related_resource, relation)


def test_remove_role_rule_relationship(set_security_resources, get_api_details):
    '''
    description:
        Check if the role and rule still exist after removing their relationship.

    wazuh_min_version:
        4.1

    parameters:
        - set_security_resources:
            type: fixture
            brief: Creates a set of role-based security resources along with a user for testing.

        - get_api_details:
            type: fixture
            brief: Get API information.

    assertions:
        - Verify that the role-rule relationship exists.
        - Verify that `status code` 200 (ok) is received when to remove the relationship.
        - Verify that the role-rule relationship is removed.
        - Verify that the role and rule still exists.

    test_input:
        From the `set_security_resources` fixture information is obtained to perform the test,
        concretely the `role_id` and `rule_id`.

    logging:
        - api.log:
            - Requests made to the API should be logged.

    tags:
        - rbac
    '''
    api_details = get_api_details()
    endpoint = api_details['base_url'] + f'/security/roles/{role_id}/rules?rule_ids={rule_id}'
    resource = role_id
    related_resource = {'rule_ids': rule_id}
    relation = 'rules'

    remove_relationship(api_details, endpoint, resource, related_resource, relation)
