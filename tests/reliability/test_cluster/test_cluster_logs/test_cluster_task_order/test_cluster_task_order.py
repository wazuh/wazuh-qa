# Copyright (C) 2015-2022, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import re
from glob import glob

import pytest

logs_format = re.compile(r'.* \[(Worker.*|Master)] \[(.*)] (.*)')
incorrect_order = {}
concatenated_tasks = {
    'Local agent-groups': {'child_task': r'Agent-groups send( full)?', 'parent_end_log': 'Starting',
                           'child_log': 'Starting', 'workers': [], 'started': False}}
worker_names = []


def test_cluster_task_order(artifacts_path):
    """Check that cluster tasks appear in the expected order.

    Check that for each concatenated task, the corresponding logs are appearing correctly.

    Args:
        artifacts_path (str): Path where folders with cluster information can be found.
    """
    if not artifacts_path:
        pytest.fail('Parameter "--artifacts_path=<path>" is required.')

    worker_log_files = glob(os.path.join(artifacts_path, 'worker_*', 'logs', 'cluster.log'))
    master_log_file = os.path.join(artifacts_path, 'master', 'logs', 'cluster.log')

    if len(worker_log_files) == 0:
        pytest.fail(f'No files found inside {artifacts_path}.')

    with open(master_log_file) as file:
        for line in file.readlines():
            # Check if the task corresponds to any of the concatenated ones.
            for parent_task, info in concatenated_tasks.items():
                if re.match(info['child_task'], line) and info['child_log'] in line and info['started']:
                    worker_name = logs_format.search(line).group(1).split(' ')[1]
                    if worker_name in info['workers'] and parent_task not in incorrect_order:
                        incorrect_order[parent_task] = {'child_task': info['child_task'], 'log': line,
                                                        'status': 'repeated'}
                        break
                    else:
                        info['workers'].append(worker_name)
                        worker_names.append(worker_name) if worker_name not in worker_names else worker_names

                if info['parent_end_log'] in line and parent_task in line:
                    if info['started']:
                        # Check if the information is already there, so we are not storing repeated situations
                        if len(info['workers']) != len(worker_names) and parent_task not in incorrect_order:
                            incorrect_order[parent_task] = {'child_task': info['child_task'],
                                                            'log': f"The following worker(s) did not performed "
                                                                   f"the '{info['child_task']}' task: "
                                                                   f"{set(worker_names) ^ set(info['workers'])}",
                                                            'status': 'missing'}
                        info['workers'].clear()
                    else:
                        info['started'] = True

            [concatenated_tasks.pop(x) for x in incorrect_order.keys() if x in concatenated_tasks]

    if incorrect_order:
        result = ''
        for key, value in incorrect_order.items():
            result = result.join(
                f"Concatenated tasks '{key}' and '{value['child_task']}' failed due to {value['status']} "
                f"logs:\n\t{value['log']}")

        pytest.fail(result)
