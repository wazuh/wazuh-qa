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
integrity_regex = compile(r'.*Compressing \'files_metadata.json\' of ([0-9]*) files.*|'
                          r'(.*Files to create: ([0-9]*) \| Files to update: '
                          r'([0-9]*) \| Files to delete: ([0-9]*) \| Files to send: ([0-9]*).*)'.encode())
repeated_syncs = {}


def test_cluster_sync(artifacts_path):
    """Check that the number of files synced is not identical multiple times in a row.

    In case that the number of files synced is identical multiple times in a row, the number of files
    for which the MD5 is calculated is also checked. If multiple identical syncs are repeated and the
    number of calculated MD5s does not change, the test is marked as failed.

    Args:
        artifacts_path (str): Path where folders with cluster information can be found.
    """
    if not artifacts_path:
        pytest.fail('Parameter "--artifacts_path=<path>" is required.')

    cluster_log_files = glob(join(artifacts_path, 'worker_*', 'logs', 'cluster.log'))
    if len(cluster_log_files) == 0:
        pytest.fail(f'No files found inside {artifacts_path}.')

    repeat_counter = 0
    for log_file in cluster_log_files:
        with open(log_file) as f:
            s = mmap(f.fileno(), 0, access=ACCESS_READ)
            sync_logs = integrity_regex.findall(s)
            if not sync_logs:
                pytest.fail(f'No integrity sync logs found in {node_name.search(log_file)[1]}')

            for i in range(len(sync_logs)):
                # Compare whether current log and the previous one are equal.
                if sync_logs[i][1] and sync_logs[i-2][1] and sync_logs[i-2][2:] == sync_logs[i][2:]:
                    # If missing files are being synced, the number of calculated MD5 should be different
                    # in the following iteration.
                    if sync_logs[i][2] != b'0' or sync_logs[i][4] != b'0':
                        # If same number of missing files is synced, MD5 count should remain the same.
                        if sync_logs[i][2] != sync_logs[i][4]:
                            if sync_logs[i-1][0] and sync_logs[i+1][0] and sync_logs[i-1] == sync_logs[i+1]:
                                repeat_counter += 1
                    # If only 1 shared file is synced, it could be the 'client.keys' so it doesn't count as a repeated
                    # log (agents could be registering).
                    elif sync_logs[i][2:] != (b'0', b'1', b'0', b'0'):
                        repeat_counter += 1

                    if repeat_counter >= configuration['repeat_threshold']:
                        repeated_syncs[node_name.search(log_file)[1]] = {
                            'log': sync_logs[i][1].decode(),
                            'repeat_counter': repeat_counter
                        }
                elif sync_logs[i][1]:
                    repeat_counter = 1

    assert not repeated_syncs, '\n' + '\n'.join('Found {repeat_counter} times in a row in {worker}: {log}'.format(
        **values, worker=worker) for worker, values in repeated_syncs.items())
