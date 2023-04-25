# Copyright (C) 2015-2022, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import copy
import json
from functools import reduce
from operator import getitem

import pytest
from wazuh_testing.tools import PYTHON_PATH


@pytest.fixture(scope='module')
def update_cluster_json(request):
    """Update cluster.json file and restart cluster nodes.

    Update cluster.json file in each node and restart it before running the test. Then, the original content
    is restored and the cluster nodes are restarted again.

    IMPORTANT: These variables must be defined in the module where this fixture is called:
      - test_hosts (list): Cluster host names.
      - host_manager (HostManager): Instance of HostManager.
      - cluster_json_values (list of dicts): Each item of the list must follow the structure below. This example:
        {'key': ['<dict_key_A>', '<dict_key_AA>'], 'value': <value>}
        would replace this value:
        {'dict_key_A': {'dict_key_AA': <REPLACED_VALUE>, 'dict_key_AB': 'unchanged_value', ...}, 'dict_key_B': ...}
    """
    backup_json = {}
    test_hosts = getattr(request.module, 'test_hosts')
    host_manager = getattr(request.module, 'host_manager')
    cluster_json_values = getattr(request.module, 'cluster_json_values')

    for host in test_hosts:
        # Find cluster.json path.
        cluster_json = host_manager.find_file(host, path=PYTHON_PATH, recurse=True, pattern='cluster.json'
                                              )['files'][0]['path']
        cluster_conf = json.loads(host_manager.run_command(host, f"cat {cluster_json}"))
        backup_json[host] = {'path': cluster_json, 'content': copy.deepcopy(cluster_conf)}

        # Update dict/nested_dicts.
        for item in cluster_json_values:
            reduce(getitem, item['key'][:-1], cluster_conf)[item['key'][-1]] = item['value']
        host_manager.modify_file_content(host=host, path=cluster_json, content=json.dumps(cluster_conf, indent=4))

        # Restart manager.
        host_manager.control_service(host=host, service='wazuh', state='restarted')

    yield

    # Restore cluster.json and restart.
    for host in backup_json:
        host_manager.modify_file_content(host=host, path=backup_json[host]['path'],
                                         content=json.dumps(backup_json[host]['content'], indent=4))
        host_manager.control_service(host=host, service='wazuh-manager', state='restarted')
