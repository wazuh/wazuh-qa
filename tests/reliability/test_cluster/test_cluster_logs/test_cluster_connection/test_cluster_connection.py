# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import re
import pytest
from glob import glob
from mmap import mmap, ACCESS_READ
from os.path import join

disconnected_nodes = []
node_name = re.compile(r'.*/(master|worker_[\d]+)/logs/cluster.log')


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

    for log_file in cluster_log_files:
        with open(log_file) as f:
            s = mmap(f.fileno(), 0, access=ACCESS_READ)
            # Search first successful connection message.
            conn = re.search(rb'^.*Successfully connected to master.*$', s, flags=re.MULTILINE)
            if not conn:
                pytest.fail(f'Could not find "Successfully connected to master" message in the '
                            f'{node_name.search(log_file)[1]}')

            # Search if there are any connection attempts after the message found above.
            if re.search(
                rb'^.*Could not connect to master. Trying.*$|^.*Successfully connected to master.*$',
                s[conn.end():],
                flags=re.MULTILINE
            ) and not re.search(
                rb'^.*The master closed the connection.*$',
                s[conn.end():],
                flags=re.MULTILINE
            ):
                disconnected_nodes.append(node_name.search(log_file)[1])

    if disconnected_nodes:
        pytest.fail(f'The following nodes disconnected from master at any point:\n- ' + '\n- '.join(disconnected_nodes))
