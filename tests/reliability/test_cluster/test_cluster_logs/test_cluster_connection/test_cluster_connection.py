# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import re
import pytest
from glob import glob
from mmap import mmap, ACCESS_READ
from os.path import join
from datetime import timedelta
from dateutil import parser

DATETIME_FORMAT = '%Y/%m/%d %H:%M'
SIGTERM_PATTERN = rb'SIGNAL \[\(15\)-\(SIGTERM\)\]'

disconnected_nodes = []
node_name = re.compile(r'.*/(master|worker_[\d]+)/logs/cluster.log')


def get_master_mmap(artifacts_path):
    """Read the master cluster log and return a mmap with the content.

    Args:
        artifacts_path (str): Path where folders with cluster information can be found.

    Returns:
        mmap (mmap): A mmap object with the master logs.
    """
    with open(join(artifacts_path, 'master', 'logs', 'cluster.log')) as master_log:
        return mmap(master_log.fileno(), 0, access=ACCESS_READ)


def test_cluster_connection(artifacts_path):
    """Verify that no worker disconnects from the master once they are connected.

    For each worker, this test looks for the first successful connection message
    in its logs. Then it looks for any failed connection attempts after the successful
    connection found above.

    Args:
        artifacts_path (str): Path where folders with cluster information can be found.
    """
    if not artifacts_path:
        pytest.fail("Parameter '--artifacts_path=<path>' is required.")

    cluster_log_files = glob(join(artifacts_path, 'worker_*', 'logs', 'cluster.log'))
    if len(cluster_log_files) == 0:
        pytest.fail(f'No files found inside {artifacts_path}.')

    master_mmap = get_master_mmap(artifacts_path=artifacts_path)

    for log_file in cluster_log_files:
        with open(log_file) as f:
            s = mmap(f.fileno(), 0, access=ACCESS_READ)
            # Search first successful connection message.
            conn = re.search(rb'^.*Successfully connected to master.*$', s, flags=re.MULTILINE)
            if not conn:
                pytest.fail(f'Could not find "Successfully connected to master" message in the '
                            f'{node_name.search(log_file)[1]}')

            # Search if there are any connection attempts after the message found above.
            finds = re.search(
                rb'^.*Could not connect to master. Trying.*$|^.*Successfully connected to master.*$',
                s[conn.end():],
                flags=re.MULTILINE
            )
            if finds:
                # Search for SIGTERM in the worker log
                end_log_timestamp = re.search(rb'(\d{4}\/\d{2}\/\d{2} \d{2}\:\d{2})', finds.group()).group()
                start_datetime = parser.parse(end_log_timestamp.decode()) - timedelta(minutes=1)
                start_log_timestamp = start_datetime.strftime(DATETIME_FORMAT)

                start_log = re.search(fr'{start_log_timestamp}.*'.encode(), s)
                worker_sigterm = re.search(SIGTERM_PATTERN, s[start_log.start():finds.start()])

                if not worker_sigterm:
                    # Search for SIGTERM in the master log
                    master_start_log = re.search(fr'{start_log_timestamp}.*'.encode(), master_mmap)
                    master_sigterm = re.search(SIGTERM_PATTERN, master_mmap[master_start_log.start():])

                    if not master_sigterm:
                        disconnected_nodes.append(node_name.search(log_file)[1])

    if disconnected_nodes:
        pytest.fail(f'The following nodes disconnected from master at any point:\n- ' + '\n- '.join(disconnected_nodes))
