# Test cluster sync

## Overview 

Check that cluster concatenated tasks follow the desired order.

Currently, there are two concatenated tasks: `Local agent-groups` and `Agent-groups send`. In this test, we are proving that the former task is executed once the latter task is finished and so on. 

## Objective

To verify that:
- Tasks are executed in the desired way.

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
python3.9 -m pytest ../../tests/reliability/test_cluster/test_cluster_logs/test_cluster_task_order/test_cluster_task_order.py --artifacts_path=/docs/final2_agent_groups/artifacts -sxvv --self-contained-html --html=report.html 
=============================================================================================== test session starts ===============================================================================================
platform linux -- Python 3.9.5, pytest-6.2.2, py-1.10.0, pluggy-0.13.1 -- /home/yanazaeva/git/wazuh-qa/wazuh_qa_env/bin/python3.9
cachedir: .pytest_cache
metadata: {'Python': '3.9.5', 'Platform': 'Linux-5.15.15-76051515-generic-x86_64-with-glibc2.31', 'Packages': {'pytest': '6.2.2', 'py': '1.10.0', 'pluggy': '0.13.1'}, 'Plugins': {'testinfra': '5.0.0', 'metadata': '1.11.0', 'html': '3.1.1'}}
rootdir: /home/yanazaeva/git/wazuh-qa
plugins: testinfra-5.0.0, metadata-1.11.0, html-3.1.1
collected 1 item                                                                                                                                                                                                  

../../tests/reliability/test_cluster/test_cluster_logs/test_cluster_task_order/test_cluster_task_order.py::test_cluster_task_order FAILED

==================================================================================================== FAILURES =====================================================================================================
_____________________________________________________________________________________________ test_cluster_task_order _____________________________________________________________________________________________

artifacts_path = '/docs/final2_agent_groups/artifacts'

    def test_cluster_task_order(artifacts_path):
        """Check that cluster tasks appear in the expected order.
    
        Check that for each concatenated tasks, the corresponding logs are apprearing correctly.
    
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
                    if info['child_task'] in line and info['child_log'] in line and info['started']:
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
                            if len(info['workers']) != len(worker_names):
                                # Check if the information is already there, so we are not storing repeated situations
                                if parent_task not in incorrect_order:
                                    incorrect_order[parent_task] = {'child_task': info['child_task'], 'log':
                                                                    f"The following worker(s) did not performed the "
                                                                    f"expected task: "
                                                                    f"{set(worker_names) ^ set(info['workers'])}",
                                                                    'status': 'missing'}
                            info['workers'].clear()
                        else:
                            info['started'] = True
    
                [concatenated_tasks.pop(x) for x in incorrect_order.keys() if x in concatenated_tasks]
    
        if incorrect_order:
            result = ''
            for key, value in incorrect_order.items():
                if value['status'] == 'repeated':
                    result += f"Concatenated tasks '{key}' and '{value['child_task']}' failed due to {value['status']} " \
                              f"logs:\n\t{value['log']}"
                elif value['status'] == 'missing':
                    result += f"Concatenated tasks '{key}' and '{value['child_task']}' failed due to {value['status']} " \
                              f"logs:\n\t{value['log']}"
    
>           pytest.fail(result)
E           Failed: Concatenated tasks 'Local agent-groups' and 'Agent-groups send' failed due to missing logs:
E           	The following worker(s) did not performed the expected task: {'CLUSTER-Workload_benchmarks_metrics_B122_manager_1'}

../../tests/reliability/test_cluster/test_cluster_logs/test_cluster_task_order/test_cluster_task_order.py:76: Failed
------------------------------------------------------------- generated html file: file:///home/yanazaeva/git/wazuh-qa/deps/wazuh_testing/report.html -------------------------------------------------------------
============================================================================================= short test summary info =============================================================================================
FAILED ../../tests/reliability/test_cluster/test_cluster_logs/test_cluster_task_order/test_cluster_task_order.py::test_cluster_task_order - Failed: Concatenated tasks 'Local agent-groups' and 'Agent-groups se...
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! stopping after 1 failures !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
================================================================================================ 1 failed in 0.05s ================================================================================================
```

### Tests information

| Number of tests | Time spent |
|:--:|:--:|
| 1 | 0.01 - 0.10s |

## Expected behavior

- Fail if a manager has executed two or more times the `Agent-groups send` task, in between two `Local agent-groups` tasks.
- Fail if a manager did not execute the `Agent-groups send` task in between two `Local agent-groups` tasks.
