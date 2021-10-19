import os

import pytest
import yaml
from wazuh_testing.tools import WAZUH_API_CONF


@pytest.fixture(scope='module')
def set_default_api_conf(request):
    hm = getattr(request.module, 'host_manager')
    new_api_conf = getattr(request.module, 'default_api_conf')
    test_hosts = getattr(request.module, 'test_hosts')
    api_tmp_backup = 'api_backup_tmp.yaml'
    api_conf_backup = dict()
    for host in test_hosts:
        api_conf_backup[host] = yaml.safe_load(hm.get_file_content(host, WAZUH_API_CONF))

    with open(api_tmp_backup, 'w') as f:
        f.write(yaml.dump(api_conf_backup))

    hm.apply_api_config(api_config=new_api_conf, host_list=test_hosts, clear_log=True)

    yield

    hm.apply_api_config(api_config=api_tmp_backup, host_list=test_hosts)
    os.remove(api_tmp_backup)


@pytest.fixture(scope='module')
def create_testing_api_user(request):
    hm = getattr(request.module, 'host_manager')
    test_hosts = getattr(request.module, 'test_hosts')

    username = 'testing_user'
    password = 'Testing1*'

    # Use the first host since users will be synchronized between all nodes
    token = hm.get_api_token(test_hosts[0])

    # Create new user
    response = hm.make_api_call(test_hosts[0], method='POST', endpoint='/security/users',
                                request_body={'username': username, 'password': password},
                                token=token)
    assert response['status'] == 200, f'Failed to create testing user: {response}'
    username_id = response['json']['data']['affected_items'][0]['id']

    # Edit allow_run_as
    response = hm.make_api_call(test_hosts[0], method='PUT',
                                endpoint=f'/security/users/{username_id}/run_as?allow_run_as=true',
                                token=token)
    assert response['status'] == 200, f'Failed to enable allow_run_as: {response}'

    # Assign administrator role
    response = hm.make_api_call(test_hosts[0], method='POST',
                                endpoint=f'/security/users/{username_id}/roles?role_ids=1',
                                token=token)
    assert response['status'] == 200, f'Failed to assign administrator role: {response}'

    setattr(request.module, 'test_user', username)
    setattr(request.module, 'test_user_id', username_id)
    setattr(request.module, 'test_passw', password)

    yield

    # Remove testing users:
    token = hm.get_api_token(test_hosts[0])

    response = hm.make_api_call(test_hosts[0], method='DELETE',
                                endpoint='/security/users?user_ids=all',
                                token=token)
    assert response['status'] == 200, f'Failed to delete testing users: {response}'


@pytest.fixture(scope='module')
def create_security_resources(request):
    hm = getattr(request.module, 'host_manager')
    test_hosts = getattr(request.module, 'test_hosts')
    token = hm.get_api_token(test_hosts[0])

    # Create testing policy
    response = hm.make_api_call(test_hosts[0], method='POST', endpoint='/security/policies',
                                request_body={'name': 'testing_policy',
                                              'policy': {
                                                  'actions': [
                                                      'agents:read'
                                                  ],
                                                  'resources': [
                                                      'agent:id:000'
                                                  ],
                                                  'effect': 'allow'
                                              }},
                                token=token)
    assert response['status'] == 200, f'Failed to create policy: {response}'
    policy_id = response['json']['data']['affected_items'][0]['id']

    # Create testing role
    response = hm.make_api_call(test_hosts[0], method='POST', endpoint='/security/roles',
                                request_body={'name': 'testing_role'},
                                token=token)
    assert response['status'] == 200, f'Failed to create policy: {response}'
    role_id = response['json']['data']['affected_items'][0]['id']

    # Create testing rule
    response = hm.make_api_call(test_hosts[0], method='POST', endpoint='/security/rules',
                                request_body={'name': 'testing_rule',
                                              'rule': {'FIND': {'username': 'testing'}}},
                                token=token)
    assert response['status'] == 200, f'Failed to create rule: {response}'
    rule_id = response['json']['data']['affected_items'][0]['id']

    # Create relation between role and policy
    response = hm.make_api_call(test_hosts[0], method='POST',
                                endpoint=f'/security/roles/{role_id}/policies?policy_ids={policy_id}',
                                token=token)
    assert response['status'] == 200, f'Failed to create relation between role and policy: {response}'

    setattr(request.module, 'test_role_id', role_id)
    setattr(request.module, 'test_policy_id', policy_id)

    # Create relation between role and rule
    response = hm.make_api_call(test_hosts[0], method='POST',
                                endpoint=f'/security/roles/1/rules?rule_ids={rule_id}',
                                token=token)
    assert response['status'] == 200, f'Failed to create relation between role and rule: {response}'

    setattr(request.module, 'test_role_id', role_id)
    setattr(request.module, 'test_rule_id', rule_id)
    setattr(request.module, 'test_policy_id', policy_id)

    yield

    token = hm.get_api_token(test_hosts[0])

    # Remove testing policies
    response = hm.make_api_call(test_hosts[0], method='DELETE',
                                endpoint='/security/policies?policy_ids=all', token=token)
    assert response['status'] == 200, f'Failed to remove testing policies: {response}'

    # Remove testing roles
    response = hm.make_api_call(test_hosts[0], method='DELETE',
                                endpoint='/security/roles?role_ids=all', token=token)
    assert response['status'] == 200, f'Failed to remove testing roles: {response}'

    # Remove testing rules
    response = hm.make_api_call(test_hosts[0], method='DELETE',
                                endpoint='/security/rules?rule_ids=all', token=token)
    assert response['status'] == 200, f'Failed to remove testing rules: {response}'
