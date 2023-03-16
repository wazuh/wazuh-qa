# Test cluster logs order

## Overview

Check that logs in the cluster nodes are printed in the expected order.

This test checks the order of the logs for the three cluster tasks (`agent-info sync`, `agent-groups recv`, `integrity check` and `integrity sync`) in the worker nodes.

## Objective

To verify that:
- The cluster does not skip any task.
- Tasks do not overlap. For example, to make sure that two Agent-info sync tasks do not start simultaneously.
- Find possible errors or unfinished tasks.

## General info
### Parameters
The test needs to receive one parameter (artifacts) in order to be run. If this parameter is not specified, the test will fail. The required parameter is:
- `--artifacts_path`: Path where cluster logs can be found inside each worker folder. It should follow the structure below:
    ```.
    ├── worker_x
    │   └── logs
    │       └── cluster.log
    ├── worker_y
    │   └── logs
    │       └── cluster.log
    └── ...
    ```
- `--html=report.html`: Create a html report with the test results.
- `--self-contained-html`: Store all the necessary data for the report inside the html file.

#### Example output
```shell
python3 -m pytest test_cluster_logs/test_cluster_worker_logs_order/test_cluster_worker_logs_order.py --artifacts_path='/tmp/artifacts/cluster_performance/59' --html=report.html --self-contained-html
============================================== test session starts ==============================================
platform linux -- Python 3.8.10, pytest-5.0.0, py-1.8.2, pluggy-0.13.1
rootdir: /home/selu/Git/wazuh-qa/tests/performance/test_cluster
plugins: metadata-1.10.0, html-3.1.1, testinfra-5.0.0, tavern-1.2.2, pep8-1.0.6, cov-2.10.0, asyncio-0.14.0
collected 1 item

test_cluster_logs/test_cluster_worker_logs_order/test_cluster_worker_logs_order.py F                                    [100%]

=================================================== FAILURES ====================================================
_________________________________________ test_check_logs_order_workers _________________________________________

artifacts_path = '/tmp/artifacts/cluster_performance/59'

    def test_check_logs_order_workers(artifacts_path):
        """Check that cluster logs appear in the expected order.

        Check that for each group of logs (agent-info, integrity-check, etc), each message
        appears in the order it should. If any log is duplicated, skipped, etc. the test will fail.

        Args:
            artifacts_path (str): Path where folders with cluster information can be found.
        """
        if not artifacts_path:
            pytest.fail('Parameter "--artifacts_path=<path>" is required.')

        if len(cluster_log_files := glob(join(artifacts_path, 'worker_*', 'logs', 'cluster.log'))) == 0:
            pytest.fail(f'No files found inside {artifacts_path}.')

        for log_file in cluster_log_files:
            with open(log_file) as file:
                for line in file.readlines():
                    if result := logs_format.search(line):
                        if result.group(1) in logs_order:
                            for child in logs_order[result.group(1)].get_children():
                                if re.search(str(child), result.group(2)):
                                    # Status of the logs_order is updated so it points to the next expected log.
                                    logs_order[result.group(1)] = child if not child.is_leaf() else child.get_root()
                                    break
                            else:
                                # Log can be different to the expected one only if permission was not granted.
                                if "Master didn't grant permission to start a new" not in result.group(2):
                                    incorrect_order.append({
                                        'node': node_name.search(log_file)[1],
                                        'log_type': result.group(1),
                                        'found_log': result.group(0),
                                        'expected_logs': [str(log) for log in logs_order[result.group(1)].get_children()]
                                    })
                                    break

            # Update status of all logs so they point to their tree root.
            logs_order.update({log_type: tree.get_root() for log_type, tree in logs_order.items()})

>       assert not incorrect_order, '\n\n'.join('{node}:\n'
                                                ' - Log type: {log_type}\n'
                                                ' - Expected logs: {expected_logs}\n'
                                                ' - Found log: {found_log}'.format(**item) for item in incorrect_order)
E       AssertionError: worker_4:
E          - Log type: Agent-info sync
E          - Expected logs: ['Permission to synchronize granted.*']
E          - Found log: 2021/09/29 12:05:57 INFO: [Worker CLUSTER-Workload_benchmarks_metrics_B59_manager_4] [Agent-info sync] Finished in 6.936s (67 chunks updated).
E       assert not [{'expected_logs': ['Permission to synchronize granted.*'], 'found_log': '2021/09/29 12:05:57 INFO: [Worker CLUSTER-Wo...ager_4] [Agent-info sync] Finished in 6.936s (67 chunks updated).', 'log_type': 'Agent-info sync', 'node': 'worker_4'}]

test_cluster_logs/test_cluster_worker_logs_order/test_cluster_worker_logs_order.py:131: AssertionError
-------- generated html file: file:///home/selu/Git/wazuh-qa/tests/performance/test_cluster/report.html ---------
=========================================== 1 failed in 0.20 seconds ============================================
```

### Adding or modifying logs order
New logs can be added inside the data folder. The content must be added as a list of dicts, following a tree structure. Therefore, each log/node can have multiple children but only one parent. If a new file is created, make sure to use the same name as the name of the task as it appears in the `cluster.log` file, replacing any ` ` (space) by `_`.

### Tests information

| Number of tests | Time spent |
|:--:|:--:|
| 1 | 0.2s |

## Expected behavior

- Fail if any log is printed when it shouldn't.
