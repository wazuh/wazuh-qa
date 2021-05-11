# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import time
from secrets import token_hex

import pytest
from wazuh_testing.tools import WAZUH_PATH
from wazuh_testing.tools.system import HostManager

# Hosts
test_hosts = ['wazuh-master', 'wazuh-worker1', 'wazuh-worker2']
worker_hosts = test_hosts[1:]
inventory_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                              'provisioning', 'agentless_cluster', 'inventory.yml')

time_to_sync = 10
host_manager = HostManager(inventory_path)
client_keys_path = os.path.join(WAZUH_PATH, "etc", "client.keys")

# Subdirectories to be synchronized.
directories_to_create = [os.path.join(WAZUH_PATH, "etc", "shared", "test_group"),
                         os.path.join(WAZUH_PATH, "var", "multigroups", "test_dir")]
# Files that, after created in the master, should be present in all nodes.
files_to_sync = [os.path.join(WAZUH_PATH, "etc", "lists", "test_file"),
                 os.path.join(WAZUH_PATH, "etc", "rules", "test_file"),
                 os.path.join(WAZUH_PATH, "etc", "decoders", "test_file"),
                 os.path.join(directories_to_create[0], 'merged.mg'),
                 os.path.join(directories_to_create[1], 'merged.mg')]
# Files inside directories where not 'all' files have to be synchronized, according to cluster.json.
files_not_to_sync = [os.path.join(WAZUH_PATH, "etc", "test_file"),
                     os.path.join(WAZUH_PATH, "etc", "lists", 'ar.conf'),
                     os.path.join(WAZUH_PATH, "etc", "lists", 'ossec.conf'),
                     os.path.join(WAZUH_PATH, "etc", "lists", 'test.tmp'),
                     os.path.join(WAZUH_PATH, "etc", "lists", 'test.lock'),
                     os.path.join(WAZUH_PATH, "etc", "lists", 'test.swp'),
                     os.path.join(directories_to_create[0], 'test_file'),
                     os.path.join(directories_to_create[1], 'test_file')]


@pytest.fixture(scope='function')
def clean_files():
    for file in files_to_sync + files_not_to_sync + directories_to_create:
        host_manager.run_command(test_hosts[0], f'rm -rf {file}')
    time.sleep(time_to_sync)


def test_missing_file(clean_files):
    """Check if missing files are copied to each node.

    Check if files that are present in the master node but not in the worker nodes are correctly copied
    to each of them. Verify that:
        - Files permissions are as expected.
        - Subdirectories are also synchronized.
        - Only specified files are synchronized (and not the rest).
        - Excluded files and extensions are not synchronized.
    """
    # Create subdirectories in the master node.
    for subdir in directories_to_create:
        host_manager.run_command(test_hosts[0], f'mkdir {subdir}')
        host_manager.run_command(test_hosts[0], f'chown wazuh:wazuh {subdir}')

    # Create all specified files inside the master node.
    for file in files_to_sync + files_not_to_sync:
        host_manager.run_command(test_hosts[0], f'touch {file}')
        host_manager.run_command(test_hosts[0], f'chown wazuh:wazuh {file}')

    # Wait until synchronization is completed. Master -> worker1 & worker2.
    time.sleep(time_to_sync)

    for host in worker_hosts:
        # Check whether files are correctly synchronized and if correct permissions are applied.
        for file in files_to_sync:
            ls_result = host_manager.run_command(host, f'ls {file}')
            assert ls_result == file, f"File {file} was expected to be copied in {host}, but it was not."
            perm = host_manager.run_command(host, f'stat -c "%a" {file}')
            assert perm == '660', f"{file} permissions were expected to be '660' in {host}, but they are {perm}."
        # Check that files which should not be synchronized are not sent to the workers. For example, only
        # merged.mg file inside /var/ossec/etc/shared/ directory should be synchronized, but nothing else.
        for file in files_not_to_sync:
            result = host_manager.run_command(host, f'ls {file}')
            assert result == '', f"File {file} was expected not to be copied in {host}, but it was."


def test_shared_files():
    """Check if the content of each file is the same in all nodes.

    Update the content of the files in the master node and check if they are updated in the workers.
    Then, update the content in the workers and check if it is overwritten by the one in the master.
    """
    # Modify the content of each file in the master node to check if it is updated in the workers.
    for file in files_to_sync:
        host_manager.modify_file_content(host=test_hosts[0], path=file, content='test_content_from_master')

    time.sleep(time_to_sync)

    # Check whether files are correctly updated in the workers.
    for host in worker_hosts:
        for file in files_to_sync:
            result = host_manager.run_command(host, f'cat {file}')
            assert result == 'test_content_from_master', f'File {file} inside {host} should contain ' \
                                                         f'"test_content_from_master", but it has: {result}'

    # Update the content of files in the worker node.
    for host in worker_hosts:
        for file in files_to_sync:
            host_manager.modify_file_content(host=host, path=file, content='test_content_from_worker')

    time.sleep(time_to_sync)

    # The only valid content of these files is the one in the master node, so all files should be overwritten again.
    for host in worker_hosts:
        for file in files_to_sync:
            result = host_manager.run_command(host, f'cat {file}')
            assert result == 'test_content_from_master', f'File {file} inside {host} should contain ' \
                                                         f'"test_content_from_master", but it has: {result}'


def test_extra_files(clean_files):
    """Check if extra files in the workers are correctly deleted.

    Create files in the worker nodes inside directories which are not marked as "extra" in the cluster.json file.
    Only valid files, except for extra_valid ones, are those created in the master. Therefore, all the files created
    in the workers should be deleted.
    """
    # Create all specified files inside the worker nodes.
    for host in worker_hosts:
        for subdir in directories_to_create:
            host_manager.run_command(test_hosts[0], f'mkdir {subdir}')
            host_manager.run_command(test_hosts[0], f'chown wazuh:wazuh {subdir}')
        for file in files_to_sync:
            host_manager.run_command(host, f'touch {file}')
            host_manager.run_command(test_hosts[0], f'chown wazuh:wazuh {file}')

    time.sleep(time_to_sync)

    # Check if the files created before have been removed in the workers, as those were not extra_valid files.
    for host in worker_hosts:
        for file in files_to_sync:
            result = host_manager.run_command(host, f'ls {file}')
            assert result == '', f"File {file} was expected to be removed from {host}, but it still exists."


def test_extra_valid_files(clean_files):
    """Check that extra_valid files created in the workers are copied in the master.

    Register two agents, wait and check that the client.keys file have been updated in all worker nodes.
    Then, each worker creates an 'agent-groups' file for one of the created agents. Files inside
    /var/ossec/queue/agent-groups are 'extra_valid' according to cluster.json, so they should be sent to the master.
    """
    # Modulesd will delete any file inside 'agent-groups' dir if its ID is not inside client.keys.
    registered_ids = list()
    for _ in range(len(worker_hosts)):
        result = host_manager.make_api_call('wazuh-master', method='POST', endpoint='/agents',
                                            request_body={'name': token_hex(16)},
                                            token=host_manager.get_api_token('wazuh-master'))
        assert result['status'] == 200, f'Failed to register agent: {result}'
        registered_ids.append(result['json']['data']['id'])

    master_client_keys = host_manager.run_command(test_hosts[0], f'cat {client_keys_path}')
    time.sleep(time_to_sync)

    for i, host in enumerate(worker_hosts):
        # Check the client.keys files is correctly updated in the workers.
        worker_client_keys = host_manager.run_command(host, f'cat {client_keys_path}')
        assert master_client_keys == worker_client_keys, f'The client.keys file is not the same in the master and' \
                                                         f'ind the {host} ->' \
                                                         f'\nMaster client keys:\n{master_client_keys}' \
                                                         f'\nWorker client keys:\n{worker_client_keys}'

        # Create an 'agent-groups' file in each worker, using the ID of the agent registered above.
        agent_groups_file = os.path.join(WAZUH_PATH, "queue", "agent-groups", registered_ids[i])
        host_manager.run_command(host, f'touch {agent_groups_file}')
        host_manager.run_command(host, f'chown wazuh:wazuh {agent_groups_file}')

    time.sleep(time_to_sync)

    # Check that the files created in the workers are in the master node now.
    for id_ in registered_ids:
        agent_groups_file = os.path.join(WAZUH_PATH, "queue", "agent-groups", id_)
        ls_result = host_manager.run_command(test_hosts[0], f'ls {agent_groups_file}')
        assert ls_result == agent_groups_file, f"File {agent_groups_file} was expected to be copied in " \
                                               f"{test_hosts[0]}, but it was not."

    # Delete the agents and the files created
    host_manager.make_api_call('wazuh-master', method='DELETE', token=host_manager.get_api_token('wazuh-master'),
                               endpoint=f'/agents?older_than=0s&agents_list={",".join(registered_ids)}')
    for id_ in registered_ids:
        host_manager.run_command(test_hosts[0], f'rm -rf {os.path.join(WAZUH_PATH, "queue", "agent-groups", id_)}')
    # Wait until they are deleted in all nodes.
    time.sleep(time_to_sync)
