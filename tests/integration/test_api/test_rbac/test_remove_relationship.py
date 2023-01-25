'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check if the 'RBAC' (Role-Based Access Control) feature of the API is working properly.
       Specifically, they will verify that the different relationships between users-roles-policies can be
       correctly removed. The 'RBAC' capability allows users accessing the API to be assigned a role
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
import requests
import pytest
from wazuh_testing.api import get_security_resource_information

# Marks
pytestmark = [pytest.mark.server]

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
@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
def test_remove_user_role_relationship(set_security_resources, get_api_details):
    '''
    description: Check if the user and role still exist after removing their relationship.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - set_security_resources:
            type: fixture
            brief: Creates a set of role-based security resources along with a user for testing.
        - get_api_details:
            type: fixture
            brief: Get API information.

    assertions:
        - Verify that the user-role relationship exists.
        - Verify that the user-role relationship is removed.
        - Verify that the user and the role still exist independently.

    inputs:
        - The testing 'user_id' as a module attribute.
        - The testing 'role_id' as a module attribute.

    input_description: From the 'set_security_resources' fixture information is obtained
                       to perform the test, concretely the 'user_id' and 'role_id'.

    expected_output:
        - A 'JSON' string in the response body with information of the user-role relationship.
        - r'200' ('OK' HTTP status code when deleting the user-role relationship)
        - A 'JSON' string in the response body with information of the role.
        - A 'JSON' string in the response body with information of the user.

    tags:
        - rbac
    '''
    api_details = get_api_details()
    endpoint = api_details['base_url'] + f'/security/users/{user_id}/roles?role_ids={role_id}'
    resource = role_id
    related_resource = {'user_ids': user_id}
    relation = 'users'

    remove_relationship(api_details, endpoint, resource, related_resource, relation)


@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
def test_remove_role_policy_relationship(set_security_resources, get_api_details):
    '''
    description: Check if the role and policy still exist after removing their relationship.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - set_security_resources:
            type: fixture
            brief: Creates a set of role-based security resources along with a user for testing.
        - get_api_details:
            type: fixture
            brief: Get API information.

    assertions:
        - Verify that the role-policy relationship exists.
        - Verify that the role-policy relationship is removed.
        - Verify that the role and the policy still exists independently.

    inputs:
        - The testing 'role_id' as a module attribute.
        - The testing 'policy_id' as a module attribute.

    input_description: From the 'set_security_resources' fixture information is obtained
                       to perform the test, concretely the 'role_id' and 'policy_id'.

    expected_output:
        - A 'JSON' string in the response body with information of the role-policy relationship.
        - r'200' ('OK' HTTP status code when deleting the role-policy relationship)
        - A 'JSON' string in the response body with information of the role.
        - A 'JSON' string in the response body with information of the policy.

    tags:
        - rbac
    '''
    api_details = get_api_details()
    endpoint = api_details['base_url'] + f'/security/roles/{role_id}/policies?policy_ids={policy_id}'
    resource = role_id
    related_resource = {'policy_ids': policy_id}
    relation = 'policies'

    remove_relationship(api_details, endpoint, resource, related_resource, relation)


@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
def test_remove_role_rule_relationship(set_security_resources, get_api_details):
    '''
    description: Check if the role and rule still exist after removing their relationship.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - set_security_resources:
            type: fixture
            brief: Creates a set of role-based security resources along with a user for testing.
        - get_api_details:
            type: fixture
            brief: Get API information.

    assertions:
        - Verify that the role-rule relationship exists.
        - Verify that the role-rule relationship is removed.
        - Verify that the role and the rule still exists independently.

    inputs:
        - The testing 'role_id' as a module attribute.
        - The testing 'rule_id' as a module attribute.

    input_description: From the 'set_security_resources' fixture information is obtained
                       to perform the test, concretely the 'role_id' and 'rule_id'.

    expected_output:
        - A 'JSON' string in the response body with information of the role-rule relationship.
        - r'200' ('OK' HTTP status code when deleting the role-rule relationship)
        - A 'JSON' string in the response body with information of the role.
        - A 'JSON' string in the response body with information of the rule.

    tags:
        - rbac
    '''
    api_details = get_api_details()
    endpoint = api_details['base_url'] + f'/security/roles/{role_id}/rules?rule_ids={rule_id}'
    resource = role_id
    related_resource = {'rule_ids': rule_id}
    relation = 'rules'

    remove_relationship(api_details, endpoint, resource, related_resource, relation)
