# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import re
from glob import glob
from os.path import join
from wazuh_testing.tools.utils import Node

import pytest

logs_format = re.compile(r'.* \[(Agent-info sync|Integrity check|Integrity sync)] (.*)')
node_name = re.compile(r'.*/(master|worker_[\d]+)/logs/cluster.log')
incorrect_order = []


# 'AGENT-INFO SYNC' LOGS
agent_info = Node(r'Agent-info sync root')
common_logs = agent_info.add_node(
    r'Permission to synchronize granted.*').add_node(
    r'Starting.*')
# No chunks obtained.
common_logs.add_node(
    r'Obtained 0 chunks of data in.*').add_node(
    r'Finished in .* \(.* chunks sent\).*')
# Chunks obtained.
chunks_sent = common_logs.add_node(r'Obtained [1-9][0-9]* chunks of data in.*')
chunks_sent.add_node(
    r'All chunks sent.*').add_node(
    r'Finished in .* \(.* chunks updated\).*')
# Race condition: 'All chunks sent' arrives (sometimes) after 'Finished in'.
chunks_sent.add_node(
    r'Finished in .* \(.* chunks updated\).*').add_node(
    r'All chunks sent.*')

# 'INTEGRITY CHECK' LOGS
integrity_check = Node('Integrity check root')
integrity_check.add_node(
    r'Permission to synchronize granted.*').add_node(
    r'Starting.*').add_node(
    r"Compressing 'files_metadata.json'.*").add_node(
    r'Sending zip file to master.*').add_node(
    r'Zip file sent to master.').add_node(
    r'Finished in .*')

# 'INTEGRITY SYNC' LOGS
integrity_sync = Node('Integrity sync root')
common_logs = integrity_sync.add_node(r'Starting.*')
# Sync anything except extra-valid files.
common_logs.add_node(
    r'Files to create: [0-9]* \| Files to update: [0-9]* \| Files to delete: [0-9]* \| Files to send: 0.*').add_node(
    r'Worker does not meet integrity checks. Actions required.*').add_node(
    r'Updating local files: Start.*').add_node(
    r'Received [0-9]* missing files to update from master.').add_node(
    r'Received [0-9]* shared files to update from master.*').add_node(
    r'Updating local files: End.').add_node(
    r'Finished in .*')
# Sync only extra-valid files.
common_logs.add_node(
    r'Files to create: 0 \| Files to update: 0 \| Files to delete: 0 \| Files to send: [1-9][0-9]*.*').add_node(
    r'Master requires some worker files.*').add_node(
    r'Starting sending extra valid files to master.*').add_node(
    r"Compressing files and 'files_metadata.json' of [0-9]* files.*").add_node(
    r'Sending zip file to master.*').add_node(
    r'Zip file sent to master.*').add_node(
    r'Finished sending extra valid files in.*').add_node(
    r'Finished in .*')
# Sync extra-valid and any other files.
common_logs.add_node(
    r'Files to create: [0-9]* \| Files to update: [0-9]* \| Files to delete: [0-9]* \| Files to send: [1-9][0-9]*.*'
).add_node(
    r'Worker does not meet integrity checks. Actions required.*').add_node(
    r'Updating local files: Start.*').add_node(
    r'Received [0-9]* missing files to update from master.').add_node(
    r'Received [0-9]* shared files to update from master.*').add_node(
    r'Updating local files: End.').add_node(
    r'Master requires some worker files.*').add_node(
    r'Starting sending extra valid files to master.*').add_node(
    r"Compressing files and 'files_metadata.json' of [0-9]* files.*").add_node(
    r'Sending zip file to master.*').add_node(
    r'Zip file sent to master.*').add_node(
    r'Finished sending extra valid files in.*').add_node(
    r'Finished in .*')

logs_order = {
    'Agent-info sync': agent_info,
    'Integrity check': integrity_check,
    'Integrity sync': integrity_sync
}


def test_check_logs_order_workers(artifacts_path):
    """Check that cluster logs appear in the expected order.

    Check that for each group of logs (agent-info, integrity-check, etc), each message
    appears in the order it should. If any log is duplicated, skipped, etc. the test will fail.

    Args:
        artifacts_path (str): Path where folders with cluster information can be found.
    """
    if not artifacts_path:
        pytest.fail('Parameter "--artifacts_path=<path>" is required.')

    if len(cluster_log_files := glob(join(artifacts_path, 'worker_*', 'logs', 'cluster.log'))) == 0:
        pytest.fail(f'No files found inside {artifacts_path}.')

    for log_file in cluster_log_files:
        with open(log_file) as file:
            for line in file.readlines():
                if result := logs_format.search(line):
                    if result.group(1) in logs_order:
                        for child in logs_order[result.group(1)].get_children():
                            if re.search(str(child), result.group(2)):
                                # Status of the logs_order is updated so it points to the next expected log.
                                logs_order[result.group(1)] = child if not child.is_leaf() else child.get_root()
                                break
                        else:
                            # Log can be different to the expected one only if permission was not granted.
                            if "Master didn't grant permission to start a new" not in result.group(2):
                                incorrect_order.append({
                                    'node': node_name.search(log_file)[1],
                                    'log_type': result.group(1),
                                    'found_log': result.group(0),
                                    'expected_logs': [str(log) for log in logs_order[result.group(1)].get_children()]
                                })
                                break

        # Update status of all logs so they point to their tree root.
        logs_order.update({log_type: tree.get_root() for log_type, tree in logs_order.items()})

    assert not incorrect_order, '\n\n'.join('{node}:\n'
                                            ' - Log type: {log_type}\n'
                                            ' - Expected logs: {expected_logs}\n'
                                            ' - Found log: {found_log}'.format(**item) for item in incorrect_order)
