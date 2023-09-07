# Test cluster connection

## Overview 

Check that there are no disconnection logs after a successful connection.

This test looks for logs like the following after a successful connection. If it finds it, it means that a worker has disconnected from the master for some reason.
```
Could not connect to master. Trying
```

## Objective

To verify that:
- All workers have connected to the master.
- No worker has disconnected after that moment.

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
python3 -m pytest test_cluster_logs/test_cluster_connection/test_cluster_connection.py --artifacts_path='/tmp/artifacts/cluster_performance/57' --html=report.html --self-contained-html
============================================================================================ test session starts ============================================================================================
platform linux -- Python 3.8.10, pytest-5.0.0, py-1.8.2, pluggy-0.13.1
rootdir: /home/selu/Git/wazuh-qa/tests/performance/test_cluster
plugins: metadata-1.10.0, html-3.1.1, testinfra-5.0.0, tavern-1.2.2, pep8-1.0.6, cov-2.10.0, asyncio-0.14.0
collected 1 item                                                                                                                                                                                            

test_cluster_logs/test_cluster_connection/test_cluster_connection.py F                                                                                                                                [100%]

================================================================================================= FAILURES ==================================================================================================
__________________________________________________________________________________________ test_cluster_connection __________________________________________________________________________________________

artifacts_path = '/tmp/artifacts/cluster_performance/57'

    def test_cluster_connection(artifacts_path):
        """Verify that no worker disconnects from the master once they are connected.
    
        For each worker, this test looks for the first successful connection message
        in its logs. Then it looks for any failed connection attempts after the successful
        connection found above.
    
        Args:
            artifacts_path (str): Path where folders with cluster information can be found.
        """
        if not artifacts_path:
            pytest.fail("Parameter '--artifacts_path=<path>' is required.")
    
        if len(cluster_log_files := glob(join(artifacts_path, 'worker_*', 'logs', 'cluster.log'))) == 0:
            pytest.fail(f'No files found inside {artifacts_path}.')
    
        for log_file in cluster_log_files:
            with open(log_file) as f:
                s = mmap(f.fileno(), 0, access=ACCESS_READ)
                # Search first successful connection message.
                if not (conn := re.search(rb'^.*Successfully connected to master.*$', s, flags=re.MULTILINE)):
                    pytest.fail(f'Could not find "Successfully connected to master" message in the '
                                f'{node_name.search(log_file)[1]}')
    
                # Search if there are any connection attempts after the message found above.
                if re.search(rb'^.*Could not connect to master. Trying.*$|^.*Successfully connected to master.*$',
                             s[conn.end():], flags=re.MULTILINE):
                    disconnected_nodes.append(node_name.search(log_file)[1])
    
        if disconnected_nodes:
>           pytest.fail(f'The following nodes disconnected from master at any point:\n- ' + '\n- '.join(disconnected_nodes))
E           Failed: The following nodes disconnected from master at any point:
E           - worker_1

test_cluster_logs/test_cluster_connection/test_cluster_connection.py:46: Failed
------------------------------------------------------ generated html file: file:///home/selu/Git/wazuh-qa/tests/performance/test_cluster/report.html -------------------------------------------------------
========================================================================================= 1 failed in 0.10 seconds ==========================================================================================
```

### Tests information

| Number of tests | Time spent |
|:--:|:--:|
| 1 | 0.1s |

## Expected behavior

- Fail if any node could not connect to the master.
- Fail if any node is disconnected after a successful connection.
