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


pytestmark = [pytest.mark.basic_cluster_env]
# Test variables

test_hosts = ['wazuh-master', 'wazuh-worker1', 'wazuh-worker2']
agent_groups = {'wazuh-agent1': ['default', 'test_mg_0'],
                'wazuh-agent2': ['default', 'test_mg_1']}

shared_folder_path = os.path.join(WAZUH_PATH, 'etc', 'shared')
mg_folder_path = os.path.join(WAZUH_PATH, 'var', 'multigroups')
inventory_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'provisioning',
                              'basic_cluster', 'inventory.yml')
host_manager = HostManager(inventory_path)

time_to_update = 10
time_to_sync = 20


# Functions

def get_api_token():
    global host_manager
    return host_manager.get_api_token(test_hosts[0])


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
                {file['path']: file['mtime'] for file in host_manager.find_file(host, folder, recurse=True)['files']}
            )

    return result


def get_agent_id(agent_name):
    """Get agent ID from its name.

    Args:
        token (str): API token.
        agent_name (str): Agent name.

    Returns:
        str: Agent ID.
    """
    agent_id = host_manager.make_api_call(host=test_hosts[0], token=get_api_token(), method='GET',
                                          endpoint=f"/agents?name={agent_name}")
    assert agent_id['status'] == 200, f"Failed trying to get ID of agent {agent_name}"
    return agent_id['json']['data']['affected_items'][0]['id']


def delete_groups():
    """Delete all groups, except Default"""
    for agent_name, groups in agent_groups.items():
        # Remove any pre-existing group.
        host_manager.make_api_call(host=test_hosts[0], token=get_api_token(), method='DELETE',
                                   endpoint=f"/groups?groups_list={','.join(groups[1:])}")

        # Remove any pre-existing multigroup (just in case they weren't removed after deleting the group).
        mg_path = os.path.join(mg_folder_path, calculate_mg_name(groups))
        host_manager.run_shell(test_hosts[0], cmd=f"rm -rf {mg_path}")
    sleep(time_to_sync)


# Fixtures

@pytest.fixture(scope='function')
def agent_healthcheck():
    """Check if expected agents are active."""
    for agent, _ in agent_groups.items():
        result = {}
        for _ in range(5):
            result = host_manager.make_api_call(host=test_hosts[0], token=get_api_token(), method='GET',
                                                endpoint=f"/agents?status=active&name={agent}")
            if result['status'] == 200 and result['json']['data']['total_affected_items'] == 1:
                break
            sleep(time_to_update)
        else:
            pytest.fail(f"Agent {agent} is not active or its status could not be checked: {result.get('json', '')}")


@pytest.fixture(scope='function')
def clean_environment():
    """Remove test groups and multigroups before and after running a test."""
    delete_groups()
    yield
    delete_groups()


@pytest.fixture(scope='function')
def create_multigroups():
    """Create expected groups and multigroups."""
    for agent_name, groups in agent_groups.items():
        for idx, group in enumerate(groups):
            if group != 'default':
                # Create group.
                response = host_manager.make_api_call(host=test_hosts[0], token=get_api_token(), method='POST',
                                                      endpoint='/groups', request_body={'group_id': group})
                assert response['status'] == 200, f"Failed to create {group} group: {response}"

                # Check that the multigroup folder does not exist yet.
                sleep(time_to_update)
                mg_name = calculate_mg_name(groups[:idx+1])
                assert not host_manager.find_file(
                    test_hosts[0], path=mg_folder_path, pattern=mg_name, file_type='directory'
                )['files'],  f"{os.path.join(mg_folder_path, mg_name)} should not exist."

                # Assign agent to group.
                agent_id = get_agent_id(agent_name=agent_name)
                response = host_manager.make_api_call(host=test_hosts[0], token=get_api_token(), method='PUT',
                                                      endpoint=f"/agents/{agent_id}/group/{group}")
                assert response['status'] == 200, f"Failed to add {agent_name} ({agent_id}) to group: {response}"

                # Check that the multigroup folder exists.
                sleep(time_to_sync)
                assert host_manager.find_file(
                    test_hosts[0], path=mg_folder_path, pattern=mg_name, file_type='directory'
                )['files'],  f"{os.path.join(mg_folder_path, mg_name)} should exist."


# Tests

def test_multigroups_not_reloaded(clean_environment, agent_healthcheck, create_multigroups):
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

    sleep(time_to_update)
    new_host_files = get_mtime(folders_to_check)

    # Check that no file was modified after some time.
    for host, files in new_host_files.items():
        for file, mtime in files.items():
            assert mtime == host_files[host][file], f"This file changed its modification time in {host}: {file}"


@pytest.mark.parametrize('target_group', [
    agent_groups['wazuh-agent1'][1],
    'default'
])
def test_multigroups_updated(clean_environment, agent_healthcheck, create_multigroups, target_group):
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
    host_manager.modify_file_content(test_hosts[0], path=os.path.join(group_path, filename), content=group_content)

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
                        assert group_content == host_manager.run_command(host, f"cat {file}"), \
                            f"The new file content is not the expected in {file}"
                    break
            else:
                assert mtime == host_files[host][file], f"This file changed its modification time in {host}: {file}"


def test_multigroups_deleted(clean_environment, agent_healthcheck, create_multigroups):
    """Check that multigroups are removed when expected.

    Unassign an agent from their groups or delete the groups. Check that the associated multigroup disappears
    in both cases.
    """
    for agent_name, groups in agent_groups.items():
        # Check that multigroups exists for each agent.
        mg_name = os.path.join(mg_folder_path, calculate_mg_name(groups))
        agent_id = get_agent_id(agent_name=agent_name)

        for group in groups:
            if group != 'default':
                if agent_name == 'wazuh-agent1':
                    # Unassign agent.
                    response = host_manager.make_api_call(host=test_hosts[0], token=get_api_token(), method='DELETE',
                                                          endpoint=f"/agents/{agent_id}/group/{group}")
                    assert response['status'] == 200, f"Failed when unassigning {agent_name} agent from " \
                                                      f"group {group}: {response}"
                else:
                    # Delete group.
                    response = host_manager.make_api_call(host=test_hosts[0], token=get_api_token(), method='DELETE',
                                                          endpoint=f"/groups?groups_list={group}")
                    assert response['status'] == 200, f"Failed to delete {group} group: {response}"

        # Check that multigroups no longer exists for each agent.
        sleep(time_to_update)
        assert not host_manager.find_file(
            test_hosts[0], path=mg_folder_path, pattern=mg_name, file_type='directory'
        )['files'], f"{os.path.join(mg_folder_path, mg_name)} should not exist."
