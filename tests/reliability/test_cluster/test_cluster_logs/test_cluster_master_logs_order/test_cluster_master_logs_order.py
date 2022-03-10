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
logs_format = re.compile(r'(.*) \[(Local agent-groups|Agent-groups full DB|Agent-groups send)] (.*)')
node_name = 'master'
incorrect_order = []


class LogsOrder:
    """This class contains the logs order object."""

    def __init__(self):
        self.logs_order = {
            ' '.join(filename.split('.')[0].split('_')): {
                'tree': dict_to_tree(safe_load(open(os.path.join(test_data_path, filename)))),
                'node': 'root'
            } for filename in os.listdir(test_data_path)
        }


def test_check_logs_order_master(artifacts_path):
    """Check that cluster logs appear in the expected order.

    Check that for each group of logs (agent-info, integrity-check, etc), each message
    appears in the order it should. If any log is duplicated, skipped, etc. the test will fail.

    Args:
        artifacts_path (str): Path where folders with cluster information can be found.
    """
    if not artifacts_path:
        pytest.fail('Parameter "--artifacts_path=<path>" is required.')

    cluster_log_files = os.path.join(artifacts_path, 'master', 'logs', 'cluster.log')

    if len(cluster_log_files) == 0:
        pytest.fail(f"No files found inside {artifacts_path}.")

    all_workers = {'Master': LogsOrder().logs_order}
    name = ''

    with open(cluster_log_files) as file:
        for line in file.readlines():
            if result := logs_format.search(line):
                if 'Worker' in result.group(1):
                    name = re.search('.*Worker (.*?)]', result.group(1)).group(1)
                    if name not in all_workers:
                        all_workers[name] = LogsOrder().logs_order
                elif 'Master' in result.group(1):
                    name = 'Master'

                if result.group(2) in all_workers[name]:
                    if 'Local agent-groups' in result.group(2) and 'Starting' in result.group(3):
                        for key, item in all_workers.items():
                            assert item['Agent-groups send'][
                                       'node'] == 'root', f"Worker {key} did not finished the 'send' task."
                    tree_info = all_workers[name][result.group(2)]
                    for child in tree_info['tree'].children(tree_info['node']):
                        if re.search(child.tag, result.group(3)):
                            # Current node is updated so the tree points to the next expected log.
                            all_workers[name][result.group(2)]['node'] = child.identifier if \
                                tree_info['tree'].children(child.identifier) else 'root'
                            break
                    else:
                        incorrect_order.append({'name': name, 'log_type': result.group(2),
                                                'expected_logs': [log.tag for log in
                                                                  tree_info['tree'].children(tree_info['node'])],
                                                'found_log': result.group(3)})
                        pytest.fail(f"[{incorrect_order[0]['name']}]"
                                    f"\n - Log type: {incorrect_order[0]['log_type']}"
                                    f"\n - Expected logs: {incorrect_order[0]['expected_logs']}"
                                    f"\n - Found log: {incorrect_order[0]['found_log']}")

    # Update status of all logs so they point to their tree root.
    for log_type, tree_info in all_workers[name].items():
        tree_info['node'] = 'root'
