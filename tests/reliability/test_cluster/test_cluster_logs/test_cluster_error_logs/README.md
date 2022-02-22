# Test cluster error logs

## Overview 

Check that there are no errors in the `cluster.log` file of any node.

This test verifies that the word `error` is not found in any cluster.log in the cluster. It is case insensitive. All logs are gathered in the `report.hml` file, if created.

## Objective

To verify that:
- There were no errors in the cluster environment, in any node.

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
python3 -m pytest test_cluster_logs/test_cluster_error_logs/test_cluster_error_logs.py --artifacts_path='/tmp/artifacts/cluster_performance/57' --html=report.html --self-contained-html
============================================================================================ test session starts ============================================================================================
platform linux -- Python 3.8.10, pytest-5.0.0, py-1.8.2, pluggy-0.13.1
rootdir: /home/selu/Git/wazuh-qa/tests/performance/test_cluster
plugins: metadata-1.10.0, html-3.1.1, testinfra-5.0.0, tavern-1.2.2, pep8-1.0.6, cov-2.10.0, asyncio-0.14.0
collected 1 item                                                                                                                                                                                            

test_cluster_logs/test_cluster_error_logs/test_cluster_error_logs.py F                                                                                                                                [100%]

================================================================================================= FAILURES ==================================================================================================
__________________________________________________________________________________________ test_cluster_error_logs __________________________________________________________________________________________

artifacts_path = '/tmp/artifacts/cluster_performance/57'

    def test_cluster_error_logs(artifacts_path):
        """Look for any error messages in the logs of the cluster nodes.
    
        Any error message that is not included in the "white_list" will cause the test to fail.
        Errors found are attached to an html report if the "--html=report.html" parameter is specified.
    
        Args:
            artifacts_path (str): Path where folders with cluster information can be found.
        """
        if not artifacts_path:
            pytest.fail('Parameter "--artifacts_path=<path>" is required.')
    
        if len(cluster_log_files := glob(join(artifacts_path, '*', 'logs', 'cluster.log'))) == 0:
            pytest.fail(f'No files found inside {artifacts_path}.')
    
        for log_file in cluster_log_files:
            with open(log_file) as f:
                s = mmap(f.fileno(), 0, access=ACCESS_READ)
                if error_lines := re.findall(rb'(^.*?error.*?$)', s, flags=re.MULTILINE | re.IGNORECASE):
                    error_lines = [error for error in error_lines if not error_in_white_list(error)]
                    if error_lines:
                        nodes_with_errors.update({node_name.search(log_file)[1]: error_lines})
    
>       assert not nodes_with_errors, 'Errors were found in the "cluster.log" file of ' \
                                      'these nodes: \n- ' + '\n- '.join(nodes_with_errors)
E       AssertionError: Errors were found in the "cluster.log" file of these nodes: 
E         - worker_4
E         - worker_2
E         - worker_24
E       assert not {'worker_2': [b'2021/09/24 12:09:27 INFO: [Worker CLUSTER-Workload_benchmarks_metrics_B57_manager_2] [Keep Alive] Erro...n error response: agent-info string could not be sent to the master node: b'Error sending request: timeout expired.'"]}

test_cluster_logs/test_cluster_error_logs/test_cluster_error_logs.py:51: AssertionError
------------------------------------------------------ generated html file: file:///home/selu/Git/wazuh-qa/tests/performance/test_cluster/report.html -------------------------------------------------------
========================================================================================= 1 failed in 0.45 seconds ==========================================================================================
```

### Adding logs to white list
It is possible to whitelist log lines so that they do not cause the test to fail. This can be useful for logs that are already checked in other tests (for example `Could not connect to master`). New logs can be added at `data/configuration.yaml`.

### Tests information

| Number of tests | Time spent |
|:--:|:--:|
| 1 | 0.5s |

## Expected behavior

- Fail if the word `error` is found in the cluster.log file of any node. 
