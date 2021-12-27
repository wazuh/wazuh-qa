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
synced_files = compile(r'(\d\d\d\d/\d\d/\d\d \d\d:\d\d:\d\d).*Files to create: ([0-9]*) \| '
                       r'Files to update: ([0-9]*) \| Files to delete: ([0-9]*) \| Files to send: ([0-9]*).*'.encode())
repeated_syncs = {}


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
                # If only 1 shared file is synced multiple times, it is the client.keys after registering agents.
                if previous_log and log[1:] == previous_log and not log[1:] == (b'0', b'1', b'0', b'0'):
                    repeat_counter += 1
                    if repeat_counter >= configuration['repeat_threshold']:
                        log = [decoded_log.decode() for decoded_log in log]
                        repeated_syncs[node_name.search(log_file)[1]] = {
                            'datetime': log[0],
                            'synced_files': f'Missing: {log[1]} | Shared: {log[2]} | Extra: {log[3]} | Extra-valid: '
                                            f'{log[4]}',
                            'repeat_counter': repeat_counter
                        }
                else:
                    previous_log = log[1:]
                    repeat_counter = 1

    assert not repeated_syncs, '\n' + '\n'.join(
        'Found {repeat_counter} times in a row in {worker} at {datetime}: {synced_files}'.format(
            **values, worker=worker) for worker, values in repeated_syncs.items()
    )
