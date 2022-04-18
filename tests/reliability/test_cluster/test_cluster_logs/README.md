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
========================================== test session starts ===========================================
platform linux -- Python 3.9.5, pytest-6.2.2, py-1.10.0, pluggy-0.13.1
rootdir: /home/yanazaeva/git/wazuh-qa
plugins: testinfra-5.0.0, metadata-1.11.0, html-3.1.1
collected 5 items                                                                                        

../../tests/reliability/test_cluster/test_cluster_logs/test_cluster_connection/test_cluster_connection.py .
../../tests/reliability/test_cluster/test_cluster_logs/test_cluster_error_logs/test_cluster_error_logs.py .
../../tests/reliability/test_cluster/test_cluster_logs/test_cluster_master_logs_order/test_cluster_master_logs_order.py .
../../tests/reliability/test_cluster/test_cluster_logs/test_cluster_sync/test_cluster_sync.py .
../../tests/reliability/test_cluster/test_cluster_logs/test_cluster_worker_logs_order/test_cluster_worker_logs_order.py .

=========================================== 5 passed in 45.08s ===========================================
========================================================================================
```

### Tests information

| Number of tests | Time spent |
|:--:|:---:|
| 5  | 45s |
