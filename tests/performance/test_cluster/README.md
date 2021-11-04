# Test cluster

## Overview 

Check the correct operation of a cluster environment using the data collected and stored in a folder that includes CSVs and log files for each node. 

## Objective

These tests check multiple aspects of a cluster, for instance:
- The time it takes for each of its tasks to complete.
- The resources used (CPU, RAM, FD, etc).
- Trends in the use of resources (any leak).
- Errors found in the logs.

## General info
### Parameters
Some tests need only one parameter (artifacts) while others need three parameters in order to be run. If those are not specified, the tests will fail. On the other hand, if all parameters are specified even if some tests do not need it, they will work fine. The required parameters are:
- `--n_workers`: Number of workers node in the cluster environment. 
- `--n_agents`: Number of agents in the cluster environment.
- `--artifacts_path`: Path where CSVs with cluster information can be found. It should follow the structure below:
    ```.
    ├── master
    │   ├── data
    │   │   ├── *
    │   │   │   ├── wazuh-clusterd.csv
    │   │   ├── *
    │   │   │   ├── agent-info_sync.csv
    │   │   │   ├── integrity_check.csv
    │   │   │   └── integrity_sync.csv
    │   └── logs
    │       └── cluster.log
    ├── worker_x
    │   ├── data
    │   │   ├── *
    │   │   │   ├── wazuh-clusterd.csv
    │   │   ├── *
    │   │   │   ├── agent-info_sync.csv
    │   │   │   ├── integrity_check.csv
    │   │   │   └── integrity_sync.csv
    │   └── logs
    │       └── cluster.log
    └── ...
    ```
- `--html=report.html`: Create a html report with the test results. 
- `--self-contained-html`: Store all the necessary data for the report inside the html file.

### Example output
```shell
python3 -m pytest . --artifacts_path='/home/selu/Descargas/cluster_performance/59' --n_agents=50000 --n_workers=10 --html=report.html --self-contained-html
============================================================================================ test session starts ============================================================================================
platform linux -- Python 3.8.10, pytest-5.0.0, py-1.8.2, pluggy-0.13.1
rootdir: /home/selu/Git/wazuh-qa/tests/performance/test_cluster
plugins: metadata-1.10.0, html-3.1.1, testinfra-5.0.0, tavern-1.2.2, pep8-1.0.6, cov-2.10.0, asyncio-0.14.0
collected 5 items                                                                                                                                                                                           

test_cluster_logs/test_cluster_connection/test_cluster_connection.py .                                                                                                                                [ 20%]
test_cluster_logs/test_cluster_error_logs/test_cluster_error_logs.py .                                                                                                                                [ 40%]
test_cluster_logs/test_cluster_logs_order/test_cluster_logs_order.py .                                                                                                                                [ 60%]
test_cluster_logs/test_cluster_sync/test_cluster_sync.py .                                                                                                                                            [ 80%]
test_cluster_performance/test_cluster_performance.py .                                                                                                                                                [100%]

------------------------------------------------------ generated html file: file:///home/selu/Git/wazuh-qa/tests/performance/test_cluster/report.html -------------------------------------------------------
========================================================================================= 5 passed in 3.50 seconds ==========================================================================================
```

### Tests information

| Number of tests | Time spent |
|:--:|:--:|
| 5 | 6s |
