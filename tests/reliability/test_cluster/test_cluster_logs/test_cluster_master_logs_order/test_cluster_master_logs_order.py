# Copyright (C) 2015-2022, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import re

import pytest
import treelib
from yaml import safe_load

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
logs_format = re.compile(
    r'(.*) \[(Local agent-groups|Agent-groups send full|Agent-groups send)] (.*)')
incorrect_order = {}


# Classes
class LogsOrder:
    """This class contains the logs order object."""

    def __init__(self):
        self.logs_order = {
            ' '.join(filename.split('.')[0].split('_')): {
                'tree': dict_to_tree(safe_load(open(os.path.join(test_data_path, filename)))),
                'node': 'root'
            } for filename in os.listdir(test_data_path)
        }


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


# Tests
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

    if not os.path.exists(cluster_log_files):
        pytest.fail(f"No files found inside {artifacts_path}.")

    all_managers = {'Master': LogsOrder().logs_order}
    name = ''

    with open(cluster_log_files) as file:
        for line in file.readlines():
            result = logs_format.search(line)
            if result:
                node_name = result.group(1)
                if 'Worker' in node_name:
                    name = re.search('.*Worker (.*?)]', node_name).group(1)
                    if name not in all_managers:
                        all_managers[name] = LogsOrder().logs_order
                elif 'Master' in node_name:
                    name = 'Master'

                log_tag = result.group(2)
                full_log = result.group(3)

                if log_tag in all_managers[name]:
                    tree_info = all_managers[name][log_tag]
                    for child in tree_info['tree'].children(tree_info['node']):
                        if re.search(child.tag, full_log):
                            # Current node is updated so the tree points to the next expected log.
                            all_managers[name][log_tag]['node'] = child.identifier if \
                                tree_info['tree'].children(child.identifier) else 'root'
                            break
                    else:
                        incorrect_order[name].append({'node': name, 'log_type': log_tag,
                                                'expected_logs': [log.tag for log in
                                                                  tree_info['tree'].children(tree_info['node'])],
                                                'found_log': full_log})
                        pytest.fail(f"[{incorrect_order[name]['node']}]"
                                    f"\n - Log type: {incorrect_order[name]['log_type']}"
                                    f"\n - Expected logs: {incorrect_order[name]['expected_logs']}"
                                    f"\n - Found log: {incorrect_order[name]['found_log']}")
