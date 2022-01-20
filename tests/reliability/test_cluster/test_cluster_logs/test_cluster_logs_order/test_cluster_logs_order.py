# Copyright (C) 2015-2022, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import re
from glob import glob

import pytest
import treelib
from yaml import safe_load


# Functions
def dict_to_tree(dict_tree):
    """Convert list of dicts (nodes) into a tree data structure.

    Args:
        dict_tree (list): List of dicts, each one with three parameters to create a tree node: log_id, parent, tag.

    Returns:
        Tree: tree data structure.
    """
    tree = treelib.Tree()
    for tree_node in dict_tree:
        tree.create_node(tree_node['tag'], tree_node['log_id'], parent=tree_node['parent'])
    return tree


# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
logs_format = re.compile(r'.* \[(Agent-info sync|Integrity check|Integrity sync)] (.*)')
node_name = re.compile(r'.*/(master|worker_[\d]+)/logs/cluster.log')
incorrect_order = []
logs_order = {
    ' '.join(filename.split('.')[0].split('_')): {
        'tree': dict_to_tree(safe_load(open(os.path.join(test_data_path, filename)))),
        'node': 'root'
    } for filename in os.listdir(test_data_path)
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

    if len(cluster_log_files := glob(os.path.join(artifacts_path, 'worker_*', 'logs', 'cluster.log'))) == 0:
        pytest.fail(f'No files found inside {artifacts_path}.')

    for log_file in cluster_log_files:
        with open(log_file) as file:
            for line in file.readlines():
                if result := logs_format.search(line):
                    if result.group(1) in logs_order:
                        tree_info = logs_order[result.group(1)]
                        for child in tree_info['tree'].children(tree_info['node']):
                            if re.search(child.tag, result.group(2)):
                                # Current node is updated so the tree points to the next expected log.
                                logs_order[result.group(1)]['node'] = child.identifier if \
                                    tree_info['tree'].children(child.identifier) else 'root'
                                break
                        else:
                            # Log can be different to the expected one only if permission was not granted.
                            if "Master didn't grant permission to start a new" not in result.group(2):
                                incorrect_order.append({
                                    'node': node_name.search(log_file)[1],
                                    'log_type': result.group(1),
                                    'found_log': result.group(0),
                                    'expected_logs': [log.tag for log in tree_info['tree'].children(tree_info['node'])]
                                })
                                break

        # Update status of all logs so they point to their tree root.
        for log_type, tree_info in logs_order.items():
            tree_info['node'] = 'root'

    assert not incorrect_order, '\n\n'.join('{node}:\n'
                                            ' - Log type: {log_type}\n'
                                            ' - Expected logs: {expected_logs}\n'
                                            ' - Found log: {found_log}'.format(**item) for item in incorrect_order)
