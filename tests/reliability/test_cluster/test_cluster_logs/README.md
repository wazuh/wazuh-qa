# Test cluster logs

## Overview 

Check the correct operation of a cluster environment using the data collected and stored in a folder that includes log files for each node. 

## Objective

These tests check multiple aspects of a cluster, for instance:
- Errors found in the logs.
- Incorrect log order in any worker node.
- Disconnections in cluster.
- Incorrect file syncing.

## General info
### Parameters
These tests need only one parameter (artifacts) in order to be run. If this parameter is not specified, the tests will fail:
- `--artifacts_path`: Path where CSVs with cluster information can be found. It should follow the structure below:
    ```.
    ├── master
    │   └── logs
    │       └── cluster.log
    ├── worker_x
    │   └── logs
    │       └── cluster.log
    └── ...
    ```
- `--html=report.html`: Create a html report with the test results. 
- `--self-contained-html`: Store all the necessary data for the report inside the html file.

### Example output
```shell
python3 -m pytest . --artifacts_path='/tmp/artifacts/cluster_performance/59' --html=report.html --self-contained-html
============================================================================================ test session starts ============================================================================================
platform linux -- Python 3.8.10, pytest-5.0.0, py-1.8.2, pluggy-0.13.1
rootdir: /home/selu/Git/wazuh-qa/tests/performance/test_cluster
plugins: metadata-1.10.0, html-3.1.1, testinfra-5.0.0, tavern-1.2.2, pep8-1.0.6, cov-2.10.0, asyncio-0.14.0
collected 5 items                                                                                                                                                                                           

test_cluster_logs/test_cluster_connection/test_cluster_connection.py .                                                                                                                                [ 20%]
test_cluster_logs/test_cluster_error_logs/test_cluster_error_logs.py .                                                                                                                                [ 40%]
test_cluster_logs/test_cluster_logs_order/test_cluster_logs_order.py .                                                                                                                                [ 60%]
test_cluster_logs/test_cluster_sync/test_cluster_sync.py .                                                                                                                                            [ 80%]                                                                                                                                            [100%]

========================================================================================= 4 passed in 3.50 seconds ==========================================================================================
```

### Tests information

| Number of tests | Time spent |
|:--:|:--:|
| 4 | 6s |
