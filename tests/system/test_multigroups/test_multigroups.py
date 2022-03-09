# Copyright (C) 2015-2022, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import hashlib
import os
import random
import string
from time import sleep

import pytest

from wazuh_testing.tools import WAZUH_PATH
from wazuh_testing.tools.system import HostManager

# Test variables

test_hosts = ['wazuh-master', 'wazuh-worker1', 'wazuh-worker2']
agent_groups = {'wazuh-agent1': ['default', 'test_mg_0'],
                'wazuh-agent2': ['default', 'test_mg_1']}

shared_folder_path = os.path.join(WAZUH_PATH, 'etc', 'shared')
mg_folder_path = os.path.join(WAZUH_PATH, 'var', 'multigroups')
inventory_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'provisioning',
                              'basic_cluster', 'inventory.yml')
hm = HostManager(inventory_path)
token = hm.get_api_token(test_hosts[0])
time_to_update = 10
time_to_sync = 20


# Functions

def calculate_mg_name(groups_list):
    """Determine multigroup name from a list of groups.

    Args:
        groups_list (list): List of groups that form a multigroup.

    Returns:
        str: Multigroup name.
    """
    return hashlib.sha256(','.join(groups_list).encode()).hexdigest()[:8]


def get_mtime(folders_to_check, hosts=None):
    """Get modification time of each file within the listed directories, for each listed host.

    Args:
        folders_to_check (iterable of str): Directories to recursively traverse to get the mtime of their files.
        hosts (list): List of hosts whose folders should be iterated.

    Returns:
        result (dict): Dictionary with the host, path and modification time of each file.
    """
    hosts = test_hosts if hosts is None else hosts
    result = {}

    for host in hosts:
        result[host] = {}
        for folder in folders_to_check:
            result[host].update(
                {file['path']: file['mtime'] for file in hm.find_file(host, folder, recurse=True)['files']}
            )

    return result


def get_agent_id(token, agent_name):
    """Get agent ID from its name.

    Args:
        token (str): API token.
        agent_name (str): Agent name.

    Returns:
        str: Agent ID.
    """
    agent_id = hm.make_api_call(host=test_hosts[0], token=token, method='GET', endpoint=f"/agents?name={agent_name}")
    assert agent_id['status'] == 200, f"Failed trying to get ID of agent {agent_name}"
    return agent_id['json']['data']['affected_items'][0]['id']


# Fixtures

@pytest.fixture(scope='module', autouse=True)
def agent_healthcheck():
    """Check if all agents are active."""
    for _ in range(10):
        result = hm.make_api_call(host=test_hosts[0], token=token, method='GET', endpoint=f'/agents?status=active')
        if result.get('json', {}).get('data', {}).get('total_affected_items', 0) == 4:
            break
        sleep(5)
    else:
        pytest.fail('Not all agents are active.')

    yield


@pytest.fixture(scope='module', autouse=True)
def clean_files():
    """Remove test groups and multigroups before and after running the tests."""
    def remove_files():
        for agent_name, groups in agent_groups.items():
            # Remove any pre-existing group.
            hm.make_api_call(host=test_hosts[0], token=hm.get_api_token(test_hosts[0]), method='DELETE',
                             endpoint=f"/groups?groups_list={','.join(groups[1:])}")

            # Remove any pre-existing multigroup (just in case they weren't removed after deleting the group).
            mg_path = os.path.join(mg_folder_path, calculate_mg_name(groups))
            for host in test_hosts:
                if hm.run_shell(host, f"ls {mg_path}") == '':
                    break
                hm.run_shell(host, cmd=f"rm -rf {mg_path}")

    remove_files()
    yield
    remove_files()


# Tests

def test_create_multigroups():
    """Check the generation of new multi-groups when an agent is assigned to groups.

    For each agent, the stipulated groups are generated and it is verified that a multigroup
    is not created. Then, assign the agent to the group and verify that the multigroup is created.
    """
    for agent_name, groups in agent_groups.items():
        for idx, group in enumerate(groups):
            if group == 'default':
                continue

            # Create group.
            response = hm.make_api_call(host=test_hosts[0], token=token, method='POST', endpoint='/groups',
                                        request_body={'group_id': group})
            assert response['status'] == 200, f"Failed to create {group} group: {response}"

            # Check that the multigroup folder does not exist yet.
            sleep(time_to_update)
            mg_path = os.path.join(mg_folder_path, calculate_mg_name(groups[:idx+1]))
            assert '' == hm.run_shell(test_hosts[0], f"ls {mg_path}"), f"{mg_path} should not exist, but it does."

            # Assign agent to group.
            agent_id = get_agent_id(token=token, agent_name=agent_name)
            response = hm.make_api_call(host=test_hosts[0], token=token, method='PUT',
                                        endpoint=f"/agents/{agent_id}/group/{group}")
            assert response['status'] == 200, f"Failed to add {agent_name} ({agent_id}) to group: {response}"

            # Check that the multigroup folder exists.
            sleep(time_to_update)
            assert '' != hm.run_shell(test_hosts[0], f"ls {mg_path}"), f"{mg_path} should exist, but it does not."


def test_multigroups_not_reloaded():
    """Check that the files are not regenerated when there are no changes.

    Check and store the modification time of all group and multigroup files. Wait 10 seconds
    and check the modification time of each file again. Verify that all files remained intact.
    """
    folders_to_check = set()
    for agent_name, groups in agent_groups.items():
        folders_to_check.update({os.path.join(shared_folder_path, group) for group in groups})
        folders_to_check.add(os.path.join(mg_folder_path, calculate_mg_name(groups)))

    # Check and store mtime of group files.
    host_files = get_mtime(folders_to_check)

    sleep(time_to_sync)
    new_host_files = get_mtime(folders_to_check)

    # Check that no file was modified after some time.
    for host, files in new_host_files.items():
        for file, mtime in files.items():
            assert mtime == host_files[host][file], f"This file changed its modification time in {host}: {file}"


@pytest.mark.parametrize('target_group', [
    random.choice(agent_groups['wazuh-agent1'][1:]),
    'default'
])
def test_multigroups_updated(target_group):
    """Check that only the appropriate multi-groups are regenerated when a group file is created.

    Check and store the modification time of all group and multigroup files. Create a new file inside
    a group. Verify that only its 'merged.mg' and the files within the affected multigroup are regenerated.

    Args:
        target_group (str): Group in which to create the new file.
    """
    folders_to_check = set()
    for agent_name, groups in agent_groups.items():
        folders_to_check.update({os.path.join(shared_folder_path, group) for group in groups})
        folders_to_check.add(os.path.join(mg_folder_path, calculate_mg_name(groups)))

    # Check and store mtime of group files.
    host_files = get_mtime(folders_to_check)

    # Add new file to any group of agent1.
    filename = f"new_file_{target_group}"
    group_content = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))
    group_path = os.path.join(shared_folder_path, target_group)
    hm.modify_file_content(test_hosts[0], path=os.path.join(group_path, filename), content=group_content)

    # Paths whose mtime should change after the new file was added.
    expected_mtime_changed = [os.path.join(group_path, filename), os.path.join(group_path, 'merged.mg')]
    expected_mtime_changed.extend([os.path.join(mg_folder_path, calculate_mg_name(groups)) for _, groups
                                   in agent_groups.items() if target_group in groups])

    sleep(time_to_sync)
    new_host_files = get_mtime(folders_to_check)

    for host, files in new_host_files.items():
        for file, mtime in files.items():
            for new_mtime_file in expected_mtime_changed:
                if new_mtime_file in file:
                    try:
                        assert mtime != host_files[host][file], f"This file should have changed in {host}: {file}"
                    except KeyError:
                        assert os.path.basename(file) == filename
                        assert group_content == hm.run_command(host, f"cat {file}"), f"The new file content is not " \
                                                                                     f"the expected in {file}"
                    break
            else:
                assert mtime == host_files[host][file], f"This file changed its modification time in {host}: {file}"


def test_multigroups_deleted():
    """Check that multigroups are removed when expected.

    Unassign an agent from their groups or delete the groups. Check that the associated
    multigroup disappears in both cases.
    """
    for agent_name, groups in agent_groups.items():
        # Check that multigroups exists for each agent.
        mg_path = os.path.join(mg_folder_path, calculate_mg_name(groups))
        assert '' != hm.run_shell(test_hosts[0], f"ls {mg_path}"), f"{mg_path} should exist, but it does not."
        agent_id = get_agent_id(token=token, agent_name=agent_name)

        for group in groups:
            if group == 'default':
                continue

            if agent_name == 'wazuh-agent1':
                # Unassign agent.
                response = hm.make_api_call(host=test_hosts[0], token=token, method='DELETE',
                                            endpoint=f"/agents/{agent_id}/group/{group}")
                assert response['status'] == 200, f"Failed when unassigning {agent_name} agent from " \
                                                  f"group {group}: {response}"
            else:
                # Delete group.
                response = hm.make_api_call(host=test_hosts[0], token=token, method='DELETE',
                                            endpoint=f"/groups?groups_list={group}")
                assert response['status'] == 200, f"Failed to delete {group} group: {response}"

        # Check that multigroups no longer exists for each agent.
        sleep(time_to_update)
        assert '' == hm.run_shell(test_hosts[0], f"ls {mg_path}"), f"{mg_path} should not exist, but it does."
