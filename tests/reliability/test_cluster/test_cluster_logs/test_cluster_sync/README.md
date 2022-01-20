# Test cluster sync

## Overview 

Check that cluster sync log is not identical multiple times in a row.

This test checks the log below is not printed more than N (`repeat_threshold`) times in a row with the same number of files. If it does, the number of files for which the MD5 is calculated is also checked. If multiple identical syncs are repeated and the number of calculated MD5s does not change, the test is marked as failed.

In that case, it could mean that the files are not being correctly synced. This could happen if, for instance, modulesd delete the synced files as soon as they are copied in the destination cluster node.
```
Files to create: N | Files to update: N | Files to delete: N | Files to send: N
```

## Objective

To verify that:
- Files are synced only once. 
- Files are not deleted in the destination node.

## General info
### Parameters
The test needs to receive one parameter  (artifacts) in order to be run. If this parameter is not specified, the test will fail. The required parameter is:
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
python3 -m pytest test_cluster_logs/test_cluster_sync/test_cluster_sync.py --artifacts_path='/tmp/artifacts/cluster_performance/59' --html=report.html --self-contained-html
============================================================================================ test session starts ============================================================================================
platform linux -- Python 3.8.10, pytest-5.0.0, py-1.8.2, pluggy-0.13.1
rootdir: /home/selu/Git/wazuh-qa/tests/performance/test_cluster
plugins: metadata-1.10.0, html-3.1.1, testinfra-5.0.0, tavern-1.2.2, pep8-1.0.6, cov-2.10.0, asyncio-0.14.0
collected 1 item                                                                                                                                                                                            

test_cluster_logs/test_cluster_sync/test_cluster_sync.py F                                                                                                                                            [100%]

================================================================================================= FAILURES ==================================================================================================
_____________________________________________________________________________________________ test_cluster_sync _____________________________________________________________________________________________

artifacts_path = '/tmp/artifacts/cluster_performance/59'

    def test_cluster_sync(artifacts_path):
        """Check that the number of files synced is not identical multiple times in a row.
    
        Args:
            artifacts_path (str): Path where folders with cluster information can be found.
        """
        if not artifacts_path:
            pytest.fail('Parameter "--artifacts_path=<path>" is required.')
    
        if len(cluster_log_files := glob(join(artifacts_path, 'worker_*', 'logs', 'cluster.log'))) == 0:
            pytest.fail(f'No files found inside {artifacts_path}.')
    
        for log_file in cluster_log_files:
            with open(log_file) as f:
                s = mmap(f.fileno(), 0, access=ACCESS_READ)
                if not (sync_logs := synced_files.findall(s)):
                    pytest.fail(f'No integrity sync logs found in {node_name.search(log_file)[1]}')
    
                previous_log = None
                for log in sync_logs:
                    if previous_log and log == previous_log:
                        repeat_counter += 1
                        if repeat_counter > configuration['repeat_threshold']:
>                           pytest.fail(f"The following sync has been found more than {configuration['repeat_threshold']} "
                                        f"times in a row in the '{node_name.search(log_file)[1]}': {log}")
E                           Failed: The following sync log has been found more than 3 times in a row in the 'worker_4': b'Files to create: 0 | Files to update: 0 | Files to delete: 0 | Files to send: 433'

test_cluster_logs/test_cluster_sync/test_cluster_sync.py:42: Failed
------------------------------------------------------ generated html file: file:///home/selu/Git/wazuh-qa/tests/performance/test_cluster/report.html -------------------------------------------------------
========================================================================================= 1 failed in 0.29 seconds ==========================================================================================
```

### Modifying threshold
The repeat threshold can be updated in the `data/configuration.yaml` file.

### Tests information

| Number of tests | Time spent |
|:--:|:--:|
| 1 | 2-5s |

## Expected behavior

- Fail if an Integrity sync log is repeated with the same number of files more than N times in a row. 
