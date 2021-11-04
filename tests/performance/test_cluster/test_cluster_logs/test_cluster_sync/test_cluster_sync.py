# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from glob import glob
from mmap import mmap, ACCESS_READ
from os.path import join, dirname, realpath
from re import compile

import pytest
from yaml import safe_load

test_data_path = join(dirname(realpath(__file__)), 'data')
configuration = safe_load(open(join(test_data_path, 'configuration.yaml')))['configuration']
node_name = compile(r'.*/(master|worker_[\d]+)/logs/cluster.log')
synced_files = compile(configuration['log_regex'].encode())


def test_cluster_sync(artifacts_path):
    """Check that the number of files synced is not identical multiple times in a row.

    Args:
        artifacts_path (str): Path where folders with cluster information can be found.
    """
    if not artifacts_path:
        pytest.fail('Parameter "--artifacts_path=<path>" is required.')

    if len(cluster_log_files := glob(join(artifacts_path, 'worker_*', 'logs', 'cluster.log'))) == 0:
        pytest.fail(f'No files found inside {artifacts_path}.')

    for log_file in cluster_log_files:
        with open(log_file) as f:
            s = mmap(f.fileno(), 0, access=ACCESS_READ)
            if not (sync_logs := synced_files.findall(s)):
                pytest.fail(f'No integrity sync logs found in {node_name.search(log_file)[1]}')

            previous_log = None
            for log in sync_logs:
                if previous_log and log == previous_log:
                    repeat_counter += 1
                    if repeat_counter > configuration['repeat_threshold']:
                        pytest.fail(f"The following sync log has been found more than "
                                    f"{configuration['repeat_threshold']} times in a row in the "
                                    f"'{node_name.search(log_file)[1]}': {log}")
                else:
                    previous_log = log
                    repeat_counter = 0
