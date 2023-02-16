# Copyright (C) 2015-2022, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import os
import time
from copy import deepcopy
from secrets import token_hex

import pytest
import yaml

from wazuh_testing.tools import WAZUH_PATH, PYTHON_PATH, WAZUH_LOGS_PATH
from wazuh_testing.tools.monitoring import HostMonitor
from wazuh_testing.tools.system import HostManager

# Hosts
test_hosts = ['wazuh-master', 'wazuh-worker1', 'wazuh-worker2']
pytestmark = [pytest.mark.cluster, pytest.mark.agentless_cluster]
worker_hosts = test_hosts[1:]
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configuration = yaml.safe_load(open(os.path.join(test_data_path, 'cluster_json.yml')))
messages_path = os.path.join(test_data_path, 'messages.yml')
tmp_path = os.path.join(test_data_path, 'tmp')
inventory_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                              'provisioning', 'agentless_cluster', 'inventory.yml')


time_to_sync = 21
host_manager = HostManager(inventory_path)
client_keys_path = os.path.join(WAZUH_PATH, 'etc', 'client.keys')

# Subdirectories to be synchronized.
directories_to_create = [os.path.join(WAZUH_PATH, 'etc', 'shared', 'test_group'),
                         os.path.join(WAZUH_PATH, 'var', 'multigroups', 'test_dir')]

# Files that, after created in the master node, should be present in all nodes.
files_to_sync = [os.path.join(WAZUH_PATH, 'etc', 'lists', 'test_file'),
                 os.path.join(WAZUH_PATH, 'etc', 'rules', 'test_file'),
                 os.path.join(WAZUH_PATH, 'etc', 'decoders', 'test_file'),
                 os.path.join(directories_to_create[1], 'merged.mg'),
                 os.path.join(directories_to_create[0], 'test_file')]

# Files inside directories where not 'all' files have to be synchronized, according to cluster.json.
files_not_to_sync = [os.path.join(WAZUH_PATH, 'etc', 'test_file'),
                     os.path.join(WAZUH_PATH, 'etc', 'lists', 'ar.conf'),
                     os.path.join(WAZUH_PATH, 'etc', 'lists', 'ossec.conf'),
                     os.path.join(WAZUH_PATH, 'etc', 'lists', 'test.tmp'),
                     os.path.join(WAZUH_PATH, 'etc', 'lists', 'test.lock'),
                     os.path.join(WAZUH_PATH, 'etc', 'lists', 'test.swp'),
                     os.path.join(directories_to_create[1], 'test_file')]

# Directories where to create big files.
tmp_size_test_path = os.path.join(WAZUH_PATH, 'tmp')
dst_size_test_path = os.path.join(WAZUH_PATH, 'etc', 'rules')
big_file_name = 'test_file_too_big'
file_prefix = 'test_file_big_'

# merged.mg and agent.conf files that must be created after creating a group folder.
merged_mg_file = os.path.join(directories_to_create[0], 'merged.mg')
agent_conf_file = os.path.join(directories_to_create[0], 'agent.conf')


# Functions

def create_file(host, path, size):
    """Create file of fixed size.

    Args:
        host (str): Host where the file should be created.
        path (str): Path and name where to create the file.
        size (int, str): Size of the file (if nothing specified, in bytes)
    """
    host_manager.run_command(host, f"fallocate -l {size} {path}")
    host_manager.run_command(host, f"chown wazuh:wazuh {path}")


# Fixtures

@pytest.fixture(scope='function')
def clean_files():
    """Remove all files that the test will create, in case they exist before starting."""
    for file in (files_to_sync + files_not_to_sync + directories_to_create +
                 [tmp_size_test_path, os.path.join(dst_size_test_path, 'test_*')]):
        host_manager.run_shell(test_hosts[0], f"rm -rf {file}")
    time.sleep(time_to_sync)


@pytest.fixture(scope='function')
def update_cluster_json():
    """Update cluster.json file and restart managers."""
    backup_json = {}

    for host in test_hosts:
        # Find cluster.json path.
        cluster_json = host_manager.find_file(host, path=PYTHON_PATH, recurse=True, pattern='cluster.json'
                                              )['files'][0]['path']
        cluster_conf = json.loads(host_manager.run_command(host, f"cat {cluster_json}"))
        # Store its original content and update the file.
        backup_json[host] = {'path': cluster_json, 'content': deepcopy(cluster_conf)}
        cluster_conf['intervals']['communication'].update(configuration)
        host_manager.modify_file_content(host=host, path=cluster_json, content=json.dumps(cluster_conf, indent=4))
        # Clear log and restart manager.
        host_manager.clear_file(host=host, file_path=os.path.join(WAZUH_LOGS_PATH, 'cluster.log'))
        host_manager.control_service(host=host, service='wazuh', state='restarted')

    yield

    # Restore cluster.json and restart.
    for host in backup_json:
        host_manager.modify_file_content(host=host, path=backup_json[host]['path'],
                                         content=json.dumps(backup_json[host]['content'], indent=4))
        # Remove created files
        for file in [tmp_size_test_path, os.path.join(dst_size_test_path, 'test_*')]:
            host_manager.run_shell(host, f"rm -rf {file}")
        host_manager.control_service(host=host, service='wazuh-manager', state='restarted')


# Tests

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
        host_manager.run_command(test_hosts[0], f"mkdir {subdir}")
        host_manager.run_command(test_hosts[0], f"chown wazuh:wazuh {subdir}")

    # Create all specified files inside the master node.
    for file in files_to_sync + files_not_to_sync + [agent_conf_file]:
        host_manager.run_command(test_hosts[0], f"dd if=/dev/urandom of={file} bs=1M count=2")
        host_manager.run_command(test_hosts[0], f"chown wazuh:wazuh {file}")

    # Wait until synchronization is completed. Master -> worker1 & worker2.
    time.sleep(time_to_sync)

    # Check whether files are correctly synchronized and if correct permissions are applied.
    for file in files_to_sync:
        master_stats = host_manager.get_stats(test_hosts[0], path=file)['stat']

        for host in worker_hosts:
            try:
                worker_stats = host_manager.get_stats(host, path=file)['stat']
                assert worker_stats['mode'] == '0660', f"{file} permissions were expected to be '660' in {host}, but " \
                                                       f"they are {worker_stats['mode']}."
                # Make sure the content of files in worker nodes is the same that in master node.
                assert worker_stats['checksum'] == master_stats['checksum'], f"The content of {file} is different in " \
                                                                             f"worker {host} and in master."
            except KeyError:
                pytest.fail(f"File {file} was expected to be copied in {host}, but it was not.")

    # Check that files which should not be synchronized are not sent to the workers. For example, only
    # merged.mg file inside /var/ossec/etc/shared/ directory should be synchronized, but nothing else.
    for file in files_not_to_sync:
        for host in worker_hosts:
            result = host_manager.run_command(host, f"ls {file}")
            assert result == '', f"File {file} was expected not to be copied in {host}, but it was."


def test_shared_files():
    """Check if the content of each file is the same in all nodes.

    Update the content of the files in the master node and check if they are updated in the workers.
    Then, update the content in the workers and check if it is overwritten by the one in the master.
    """
    agent_conf_content = '<agent_config></agent_config>'
    file_test_content_master = 'test_content_from_master'
    file_test_content_worker = 'test_content_from_worker'

    # Modify the content of each file in the master node to check if it is updated in the workers.
    for file in files_to_sync:
        host_manager.modify_file_content(host=test_hosts[0], path=file, content=file_test_content_master)

    # Modify the content of the agent.conf file to check if merged.mg file is updated in master and synchronized in
    # workers.
    host_manager.modify_file_content(host=test_hosts[0], path=agent_conf_file, content=f"{agent_conf_content}\n")
    time.sleep(time_to_sync)

    # Check whether files are correctly updated in the workers or not.
    for host in worker_hosts:
        for file in files_to_sync:
            result = host_manager.run_command(host, f"cat {file}")
            assert result == file_test_content_master, f"File {file} inside {host} should contain " \
                                                       f"{file_test_content_master}, but it has: {result}"

    # Check whether the merged.mg file is correctly updated in master and synchronized in workers or not.
    for host in test_hosts:
        result = host_manager.run_command(host, f"cat {merged_mg_file}")
        # The agent.conf content will be before the !0 test_file line in merged.mg.
        assert agent_conf_content in result, f"File {merged_mg_file} inside {host} should contain " \
                                             f"{agent_conf_content}, but it has: {result} "

    # Check whether the agent.conf file is correctly updated in master and synchronized in workers or not.
    agent_conf_content = host_manager.run_command(test_hosts[0], f"cat {agent_conf_file}")
    for host in test_hosts:
        result = host_manager.run_command(host, f"cat {agent_conf_file}")
        assert agent_conf_content in result, f"File {agent_conf_file} inside {host} should contain " \
                                             f"{agent_conf_content}, but it has: {result} "

    # Update the content of files in the worker node.
    for host in worker_hosts:
        for file in files_to_sync:
            host_manager.modify_file_content(host=host, path=file, content=file_test_content_worker)

    time.sleep(time_to_sync)

    # The only valid content of these files is the one in the master node, so all files should be overwritten again.
    for host in worker_hosts:
        for file in files_to_sync:
            result = host_manager.run_command(host, f"cat {file}")
            assert result == file_test_content_master, f"File {file} inside {host} should contain " \
                                                       f"{file_test_content_master}, but it has: {result}"


def test_extra_files(clean_files):
    """Check if extra files in the workers are correctly deleted.

    Create files in the worker nodes inside directories which are not marked as "extra" in the cluster.json file.
    Only valid files, except for extra_valid ones, are those created in the master. Therefore, all the files created
    in the workers should be deleted.
    """
    # Create all specified files inside the worker nodes.
    for host in worker_hosts:
        for subdir in directories_to_create:
            host_manager.run_command(test_hosts[0], f"mkdir {subdir}")
            host_manager.run_command(test_hosts[0], f"chown wazuh:wazuh {subdir}")
        for file in files_to_sync:
            host_manager.run_command(host, f"touch {file}")
            host_manager.run_command(test_hosts[0], f"chown wazuh:wazuh {file}")

    time.sleep(time_to_sync)

    # Check if the files created before have been removed in the workers, as those were not extra_valid files.
    for host in worker_hosts:
        for file in files_to_sync:
            result = host_manager.run_command(host, f"ls {file}")
            assert result == '', f"File {file} was expected to be removed from {host}, but it still exists."


def test_zip_size_limit(clean_files, update_cluster_json):
    """Check if zip size limit works and if it is dynamically adapted.

    Create several large files on the master. The time needed to send them all together
    should exceed the maximum time allowed and a timeout should be generated on the workers.
    The test verifies that:
        - Workers notify the master to cancel the file being sent.
        - The master reduces the zip size limit.
        - The master warns that a file that is too large will not be synchronized.
        - The master warns that not all the files could be synchronized since they did not fit in the zip.
        - Eventually the zip size limit is increased again.
        - The workers end up receiving all the files that do not exceed the maximum size.
    """
    too_big_size = configuration['max_zip_size'] + 1024
    big_size = configuration['min_zip_size'] - 1024
    big_filenames = {file_prefix + str(i) for i in range(5)}

    # Create a tmp folder and all files inside in the master node.
    host_manager.run_command(test_hosts[0], f"mkdir {tmp_size_test_path}")
    create_file(test_hosts[0], os.path.join(tmp_size_test_path, big_file_name), too_big_size)
    for filename in big_filenames:
        create_file(test_hosts[0], os.path.join(tmp_size_test_path, filename), big_size)

    # Move files from tmp folder to destination folder. This way, all files are synced at the same time.
    host_manager.run_shell(test_hosts[0], f"mv {os.path.join(tmp_size_test_path, 'test_*')} {dst_size_test_path}")

    # Check whether zip size limit changed, big files are rejected, etc.
    HostMonitor(inventory_path=inventory_path, messages_path=messages_path, tmp_path=tmp_path).run()

    for host in worker_hosts:
        # Make sure that smaller files were synced.
        worker_files = {file['path'] for file in host_manager.find_file(host, path=dst_size_test_path,
                                                                        pattern=file_prefix, use_regex=True)['files']}
        assert worker_files == {os.path.join(dst_size_test_path, file) for file in big_filenames}, \
            f"Not all expected files were found in {host}."

        # While too big files were rejected.
        assert not host_manager.find_file(host, path=dst_size_test_path, pattern=big_file_name)['files'], \
            f"File {big_file_name}' was expected not to be copied in {host}, but it was."
