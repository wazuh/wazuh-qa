# Test cluster logs order

## Overview 

Check that logs in the cluster nodes are printed in the expected order.

This test checks the order of the logs for the three cluster tasks (`agent-groups send`, `Local agent-groups` and `agent-groups full DB`) in the master nodes. 

## Objective

To verify that:
- The cluster does not skip any task. The master node does not skip any cluster's task.
- Tasks do not overlap. For example, to make sure that two Agent-info sync tasks do not start simultaneously.
- Find possible errors or unfinished tasks.

## General info
### Parameters
The test needs to receive one parameter (artifacts) in order to be run. If this parameter is not specified, the test will fail. The required parameter is:
- `--artifacts_path`: Path where cluster logs can be found inside the master folder. It should follow the structure below:
    ```.
    ├── master
    │   └── logs
    │       └── cluster.log
    ```
- `--html=report.html`: Create a html report with the test results. 
- `--self-contained-html`: Store all the necessary data for the report inside the html file.

#### Example output
```shell
pytest tests/reliability/test_cluster/test_cluster_logs/test_cluster_master_logs_order/ --artifacts_path=/docs/agent_groups --html=report.html --self-contained-html -sxvv 
========================================== test session starts ==========================================
platform linux -- Python 3.9.5, pytest-6.2.2, py-1.10.0, pluggy-0.13.1
rootdir: /home/yanazaeva/git/wazuh-qa
plugins: testinfra-5.0.0, metadata-1.11.0, html-3.1.1
collected 1 item                                                                                        

tests/reliability/test_cluster/test_cluster_logs/test_cluster_master_logs_order/test_cluster_master_logs_order.py F [100%]

=============================================== FAILURES ================================================
_____________________________________ test_check_logs_order_master ______________________________________

artifacts_path = '/docs/agent_groups'

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
    
        if len(cluster_log_files) == 0:
            pytest.fail(f"No files found inside {artifacts_path}.")
    
        all_managers = {'Master': LogsOrder().logs_order}
        name = ''
    
        with open(cluster_log_files) as file:
            for line in file.readlines():
                result = logs_format.search(line)
                if result:
                    if 'Worker' in result.group(1):
                        name = re.search('.*Worker (.*?)]', result.group(1)).group(1)
                        if name not in all_managers:
                            all_managers[name] = LogsOrder().logs_order
                    elif 'Master' in result.group(1):
                        name = 'Master'
    
                    if result.group(2) in all_managers[name]:
                        if 'Local agent-groups' in result.group(2) and 'Starting' in result.group(3):
                            for key, item in all_managers.items():
                                assert item['Agent-groups send'][
                                           'node'] == 'root', f"Worker {key} did not finished the 'send' task."
                        tree_info = all_managers[name][result.group(2)]
                        for child in tree_info['tree'].children(tree_info['node']):
                            if re.search(child.tag, result.group(3)):
                                # Current node is updated so the tree points to the next expected log.
                                all_managers[name][result.group(2)]['node'] = child.identifier if \
                                    tree_info['tree'].children(child.identifier) else 'root'
                                break
                        else:
                            incorrect_order.append({'name': name, 'log_type': result.group(2),
                                                    'expected_logs': [log.tag for log in
                                                                      tree_info['tree'].children(tree_info['node'])],
                                                    'found_log': result.group(3)})
>                           pytest.fail(f"[{incorrect_order[0]['name']}]"
                                        f"\n - Log type: {incorrect_order[0]['log_type']}"
                                        f"\n - Expected logs: {incorrect_order[0]['expected_logs']}"
                                        f"\n - Found log: {incorrect_order[0]['found_log']}")
E                           Failed: [CLUSTER-Workload_benchmarks_metrics_B77_manager_1]
E                            - Log type: Agent-groups send
E                            - Expected logs: ['Finished in.*chunks updated.*']
E                            - Found log: Starting.

tests/reliability/test_cluster/test_cluster_logs/test_cluster_master_logs_order/test_cluster_master_logs_order.py:96: Failed
======================================== short test summary info ========================================
FAILED tests/reliability/test_cluster/test_cluster_logs/test_cluster_master_logs_order/test_cluster_master_logs_order.py::test_check_logs_order_master
=========================================== 1 failed in 0.18s ===========================================
```

### Adding or modifying logs order
New logs can be added inside the data folder. The content must be added as a list of dicts, following a tree structure. Therefore, each log/node can have multiple children but only one parent. If a new file is created, make sure to use the same name as the name of the task as it appears in the `cluster.log` file, replacing any ` ` (space) by `_`.

### Tests information

| Number of tests | Time spent |
|:--:|:--:|
| 1 | 0.33s |

## Expected behavior

- Fail if any log is printed when it shouldn't.
