# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import re
from glob import glob
from mmap import mmap, ACCESS_READ
from os.path import join, dirname, realpath

import pytest
from yaml import safe_load

test_data_path = join(dirname(realpath(__file__)), 'data')
white_list = [log.encode() for log in safe_load(open(join(test_data_path, 'configuration.yaml')))['white_list']]
node_name = re.compile(r'.*/(master|worker_[\d]+)/logs/cluster.log')
nodes_with_errors = {}


# Functions
def error_in_white_list(error_str):
    """Check if error message is whitelisted.

    Args:
        error_str (str): Error message to be searched in the white list.

    Returns:
        bool: Whether the message is whitelisted or not.
    """
    return any(line in error_str for line in white_list)


def test_cluster_error_logs(artifacts_path):
    """Look for any error messages in the logs of the cluster nodes.

    Any error message that is not included in the "white_list" will cause the test to fail.
    Errors found are attached to an html report if the "--html=report.html" parameter is specified.

    Args:
        artifacts_path (str): Path where folders with cluster information can be found.
    """
    if not artifacts_path:
        pytest.fail('Parameter "--artifacts_path=<path>" is required.')

    cluster_log_files = glob(join(artifacts_path, '*', 'logs', 'cluster.log'))
    if len(cluster_log_files) == 0:
        pytest.fail(f'No files found inside {artifacts_path}.')

    for log_file in cluster_log_files:
        with open(log_file) as f:
            s = mmap(f.fileno(), 0, access=ACCESS_READ)
            error_lines = re.findall(rb'(^.*?error.*?$)', s, flags=re.MULTILINE | re.IGNORECASE)
            if error_lines:
                error_lines = [error for error in error_lines if not error_in_white_list(error)]
                if error_lines:
                    nodes_with_errors.update({node_name.search(log_file)[1]: error_lines})

    assert not nodes_with_errors, 'Errors were found in the "cluster.log" file of ' \
                                  'these nodes: \n- ' + '\n- '.join(nodes_with_errors)
