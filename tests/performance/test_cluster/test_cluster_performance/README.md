# Test cluster performance

## Overview 

Check that a cluster environment did not exceed certain thresholds.

It obtains various statistics (mean, max, regression coefficient) from CSVs with data generated in a cluster environment (resources used and duration of tasks). These statistics are compared with thresholds established in the data folder.
## Objective

To confirm that a cluster environment does not exceed certain thresholds in:
- Duration of tasks (agent-info sync, integrity check and integrity sync).
- Usage of resources (RAM, File descriptors, CPU).
- Trends in the use of resources (any leak).

## General info
### Parameters
The test needs to receive three parameters in order to be run. If these parameters are not specified, the test will fail. The required parameters are:
- `--n_workers`: Number of workers nodes in the cluster environment. 
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
    ├── worker_x
    │   ├── data
    │   │   ├── *
    │   │   │   ├── wazuh-clusterd.csv
    │   │   ├── *
    │   │   │   ├── agent-info_sync.csv
    │   │   │   ├── integrity_check.csv
    │   │   │   └── integrity_sync.csv
    └── ...
    ```
- `--html=report.html`: Create a html report with the test results. 
- `--self-contained-html`: Store all the necessary data for the report inside the html file.

#### Example output
```shell
python3 -m pytest test_cluster_performance.py --artifacts_path='/tmp/artifacts/cluster_performance/74' --n_workers=10 --n_agents=50000 --html=report.html --self-contained-html
============================================================================================ test session starts ============================================================================================
platform linux -- Python 3.8.10, pytest-5.0.0, py-1.8.2, pluggy-0.13.1
rootdir: /home/selu/Git/wazuh-qa/tests/performance/test_cluster
plugins: metadata-1.10.0, html-3.1.1, testinfra-5.0.0, tavern-1.2.2, pep8-1.0.6, cov-2.10.0, asyncio-0.14.0
collected 1 item                                                                                                                                                                                            

test_cluster_performance.py F                                                                                                                                                                         [100%]

================================================================================================= FAILURES ==================================================================================================
_________________________________________________________________________________________ test_cluster_performance __________________________________________________________________________________________

artifacts_path = '/tmp/artifacts/cluster_performance/74', n_workers = '10', n_agents = '50000'

    def test_cluster_performance(artifacts_path, n_workers, n_agents):
        """Check that a cluster environment did not exceed certain thresholds.
    
        This test obtains various statistics (mean, max, regression coefficient) from CSVs with
        information of a cluster environment (resources used and duration of tasks). These
        statistics are compared with thresholds established in the data folder.
    
        Args:
            artifacts_path (str): Path where CSVs with cluster information can be found.
            n_workers (int): Number of workers folders that are expected inside the artifacts path.
            n_agents (int): Number of agents in the cluster environment.
        """
        if None in (artifacts_path, n_workers, n_agents):
            pytest.fail("Parameters '--artifacts_path=<path> --n_workers=<n_workers> --n_agents=<n_agents>' are required.")
    
        # Check if there are threshold data for the specified number of workers and agents.
        if (selected_conf := f"{n_workers}w_{n_agents}a") not in configurations:
            pytest.fail(f"This is not a supported configuration: {selected_conf}. "
                        f"Supported configurations are: {', '.join(configurations.keys())}.")
    
        # Check if path exists and if expected number of workers matches what is found inside artifacts.
        try:
            cluster_info = ClusterEnvInfo(artifacts_path).get_all_info()
        except FileNotFoundError:
            pytest.fail(f'Path "{artifacts_path}" could not be found or it may not follow the proper structure.')
    
        if cluster_info.get('worker_nodes', 0) != int(n_workers):
            pytest.fail(f'Information of {n_workers} workers was expected, but {cluster_info.get("worker_nodes", 0)} '
                        f'were found.')
    
        # Calculate stats from data inside artifacts path.
        data = {'tasks': ClusterCSVTasksParser(artifacts_path).get_stats(),
                'resources': ClusterCSVResourcesParser(artifacts_path).get_stats()}
    
        if not data['tasks'] or not data['resources']:
            pytest.fail(f'Stats could not be retrieved, "{artifacts_path}" path may not exist, it is empty or it may not'
                        f' follow the proper structure.')
    
        # Compare each stat with its threshold.
        for data_name, data_stats in data.items():
            for phase, files in data_stats.items():
                for file, columns in files.items():
                    for column, nodes in columns.items():
                        for node_type, stats in nodes.items():
                            for stat, value in stats.items():
                                th_value = configurations[selected_conf][data_name][phase][file][column][node_type][stat]
                                if value[1] >= th_value:
                                    exceeded_thresholds.append({'value': value[1], 'threshold': th_value, 'stat': stat,
                                                                'column': column, 'node': value[0], 'file': file,
                                                                'phase': phase})
    
        try:
            output = '\n - '.join('{stat} {column} {value} >= {threshold} ({node}, {file}, '
                                  '{phase})'.format(**item) for item in exceeded_thresholds)
>           assert not exceeded_thresholds, f"Some thresholds were exceeded:\n - {output}"
E           AssertionError: Some thresholds were exceeded:
E              - max time_spent(s) 9.43 >= 9 (worker_10, integrity_check, stable_phase)
E              - max time_spent(s) 10.233 >= 10 (worker_10, agent-info_sync, stable_phase)
E           assert not [{'column': 'time_spent(s)', 'file': 'integrity_check', 'node': 'worker_10', 'phase': 'stable_phase', ...}, {'column': 'time_spent(s)', 'file': 'agent-info_sync', 'node': 'worker_10', 'phase': 'stable_phase', ...}]

test_cluster_performance.py:101: AssertionError
------------------------------------------------------------------------------------------- Captured stdout call --------------------------------------------------------------------------------------------
Setup phase took 0:10:11s (2021/10/15 15:39:41 - 2021/10/15 15:49:52).
Stable phase took 0:13:47s (2021/10/15 15:49:52 - 2021/10/15 16:03:39).
------------------------------------------------------ generated html file: file:///home/selu/Git/wazuh-qa/tests/performance/test_cluster/report.html -------------------------------------------------------
========================================================================================= 1 failed in 0.45 seconds ==========================================================================================

```

### Adding or modifying thresholds
New thresholds files can be added inside the `data` folder of the test. The filename must follow this structure:
- `<number_of_workers>w_<number_of_agents>a_thresholds.yaml`

The content must be a yaml with two main keys, `tasks` and `resources`. Each of them must contain the same information that is produced when executing the `ClusterCSVTasksParser` and `ClusterCSVResourcesParser` tools of `wazuh_testing.tools.performance.csv_parser`.

### Tests information

| Number of tests | Time spent |
|:--:|:--:|
| 1 | 0.2s |

## Expected behavior

- Fail if the stats obtained from cluster CSVs exceeds any threshold defined inside `data` path.
