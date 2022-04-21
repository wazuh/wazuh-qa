# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from os import listdir
from os.path import join, dirname, realpath

import pytest
from yaml import safe_load

from wazuh_testing.tools.performance.csv_parser import ClusterCSVTasksParser, ClusterCSVResourcesParser, ClusterEnvInfo
from wazuh_testing.tools.utils import get_datetime_diff

test_data_path = join(dirname(realpath(__file__)), 'data')
configurations = {file.replace('_thresholds.yaml', ''): safe_load(open(join(test_data_path, file))) for file in
                  listdir(test_data_path)}
date_format = '%Y/%m/%d %H:%M:%S'
exceeded_thresholds = []


# Fixtures
@pytest.fixture()
def n_workers(pytestconfig):
    return pytestconfig.getoption('n_workers')


@pytest.fixture()
def n_agents(pytestconfig):
    return pytestconfig.getoption('n_agents')


def test_cluster_performance(artifacts_path, n_workers, n_agents):
    """Check that a cluster environment did not exceed certain thresholds.

    This test obtains various statistics (mean, max, regression coefficient) from CSVs with
    data generated in a cluster environment (resources used and duration of tasks). These
    statistics are compared with thresholds established in the data folder.

    Args:
        artifacts_path (str): Path where CSVs with cluster information can be found.
        n_workers (int): Number of workers folders that are expected inside the artifacts path.
        n_agents (int): Number of agents in the cluster environment.
    """
    if None in (artifacts_path, n_workers, n_agents):
        pytest.fail("Parameters '--artifacts_path=<path> --n_workers=<n_workers> --n_agents=<n_agents>' are required.")

    # Check if there are threshold data for the specified number of workers and agents.
    selected_conf = f"{n_workers}w_{n_agents}a"
    if selected_conf not in configurations:
        pytest.fail(f"This is not a supported configuration: {selected_conf}. "
                    f"Supported configurations are: {', '.join(configurations.keys())}.")

    # Check if path exists and if expected number of workers matches what is found inside artifacts.
    try:
        cluster_info = ClusterEnvInfo(artifacts_path).get_all_info()
    except FileNotFoundError:
        pytest.fail(f"Path '{artifacts_path}' could not be found or it may not follow the proper structure.")

    if cluster_info.get('worker_nodes', 0) != int(n_workers):
        pytest.fail(f"Information of {n_workers} workers was expected inside the artifacts folder, but "
                    f"{cluster_info.get('worker_nodes', 0)} were found.")

    # Calculate stats from data inside artifacts path.
    data = {'tasks': ClusterCSVTasksParser(artifacts_path).get_stats(),
            'resources': ClusterCSVResourcesParser(artifacts_path).get_stats()}

    if not data['tasks'] or not data['resources']:
        pytest.fail(f"Stats could not be retrieved, '{artifacts_path}' path may not exist, it is empty or it may not"
                    f" follow the proper structure.")

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
        assert not exceeded_thresholds, 'Some thresholds were exceeded:\n- ' + '\n- '.join(
            '{stat} {column} {value} >= {threshold} ({node}, {file}, {phase})'.format(**item) for item in
            exceeded_thresholds)
    finally:
        # Add useful information to report as stdout
        try:
            print(f"\nSetup phase took {get_datetime_diff(cluster_info['phases']['setup_phase'], date_format)}s "
                  f"({cluster_info['phases']['setup_phase'][0]} - {cluster_info['phases']['setup_phase'][1]}).")
            print(f"Stable phase took {get_datetime_diff(cluster_info['phases']['stable_phase'], date_format)}s "
                  f"({cluster_info['phases']['stable_phase'][0]} - {cluster_info['phases']['stable_phase'][1]}).")
        except KeyError:
            print('No information available about test phases.')
