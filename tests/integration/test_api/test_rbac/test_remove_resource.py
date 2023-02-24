'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check if the 'RBAC' (Role-Based Access Control) feature of the API is working properly.
       Specifically, they will verify that the different security resources (users, roles, policies, and rules)
       can be correctly removed. The 'RBAC' capability allows users accessing the API to be assigned a role that
       will define the privileges they have.

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
@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
def test_remove_rule(set_security_resources, get_api_details):
    '''
    description: Check if relationships between security resources stay the same
                 after removing the linked rule.

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
        - Verify that the role-based relationships exist.
        - Verify that the request to delete the linked rule is done correctly.
        - Verify that the role-based security relationships still exist.
        - Verify that the remaining security resources still exist (user, role, and policy).
        - Verify that the remaining role-based security relationships still exist.

    inputs:
        - The testing 'role_id' as a module attribute.
        - The testing 'rule_id' as a module attribute.

    input_description: From the 'set_security_resources' fixture information is obtained
                       to perform the test, concretely the 'role_id' and the 'rule_id'.

    expected_output:
        - A 'JSON' string in the response body with information of the role-based relationships.
        - r'200' ('OK' HTTP status code when deleting the linked rule)

    tags:
        - rbac
    '''
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


@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
def test_remove_policy(set_security_resources, get_api_details):
    '''
    description: Check if relationships between security resources stay the same
                 after removing the linked policy.

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
        - Verify that the role-based relationships exist.
        - Verify that the request to delete the linked policy is done correctly.
        - Verify that the role-based security relationships still exist.
        - Verify that the remaining security resources still exist (user, role, and rule).
        - Verify that the remaining role-based security relationships still exist.

    inputs:
        - The testing 'role_id' as a module attribute.
        - The testing 'policy_id' as a module attribute.

    input_description: From the 'set_security_resources' fixture information is obtained
                       to perform the test, concretely the 'role_id' and the 'policy_id'.

    expected_output:
        - A 'JSON' string in the response body with information of the role-based relationships.
        - r'200' ('OK' HTTP status code when deleting the linked policy)

    tags:
        - rbac
    '''
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


@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
def test_remove_user(set_security_resources, get_api_details):
    '''
    description: Check if relationships between security resources stay the same
                 after removing the linked user.

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
        - Verify that the role-based relationships exist.
        - Verify that the request to delete the linked user is done correctly.
        - Verify that the role-based security relationships still exist.
        - Verify that the remaining security resources still exist (policy, role, and rule).
        - Verify that the remaining role-based security relationships still exist.

    inputs:
        - The testing 'role_id' as a module attribute.
        - The testing 'user_id' as a module attribute.

    input_description: From the 'set_security_resources' fixture information is obtained
                       to perform the test, concretely the 'role_id' and the 'user_id'.

    expected_output:
        - A 'JSON' string in the response body with information of the role-based relationships.
        - r'200' ('OK' HTTP status code when deleting the linked user)

    tags:
        - rbac
    '''
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


@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
def test_remove_role(set_security_resources, get_api_details):
    '''
    description: Check if relationships between security resources stay the same
                 after removing the linked role.

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
        - Verify that the role-based relationships exist.
        - Verify that the request to delete the linked role is done correctly.
        - Verify that the role-based security relationships still exist.
        - Verify that the remaining security resources still exist (policy, user, and rule).
        - Verify that the remaining role-based security relationships still exist.

    inputs:
        - The testing 'user_id' as a module attribute.
        - The testing 'role_id' as a module attribute.

    input_description: From the 'set_security_resources' fixture information is obtained
                       to perform the test, concretely the 'user_id' and the 'role_id'.

    expected_output:
        - A 'JSON' string in the response body with information of the role-based relationships.
        - r'200' ('OK' HTTP status code when deleting the linked role)

    tags:
        - rbac
    '''
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
