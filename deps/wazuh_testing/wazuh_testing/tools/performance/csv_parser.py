# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from collections import defaultdict
from glob import glob
from os.path import join
from pathlib import Path
from re import compile

import numpy as np
import pandas as pd

aggregation_function = {
    "Daemon": "first",
    "Version": "first",
    "PID": "first",
    "CPU(%)": "sum",
    "VMS(KB)": "sum",
    "RSS(KB)": "sum",
    "USS(KB)": "sum",
    "PSS(KB)": "sum",
    "SWAP(KB)": "sum",
    "FD": "sum",
    "Read_Ops": "sum",
    "Write_Ops": "sum",
    "Disk_Read(KB)": "sum",
    "Disk_Written(KB)": "sum",
    "Disk_Read_Speed(KB/s)": "sum",
    "Disk_Write_Speed(KB/s)": "sum"
}


class ClusterCSVParser:
    """Class to load and parse CSVs with data produced by the Wazuh cluster.

    Args:
        artifacts_path (str): directory where the cluster CSVs can be found.
        files_to_load (list): CSV filenames (without extension) that should be loaded.

    Attributes:
        artifacts_path (str): directory where the cluster CSVs can be found.
        files_to_load (list): CSV filenames (without extension) that should be loaded.
        dataframes (dict): dictionary with dataframes obtained from the loaded CSV files.
    """

    SETUP_PHASE = 'setup_phase'
    STABLE_PHASE = 'stable_phase'

    def __init__(self, artifacts_path, files_to_load):
        self.artifacts_path = artifacts_path
        self.files_to_load = files_to_load
        self.dataframes = defaultdict(lambda: defaultdict(lambda: defaultdict(None)))

        self._load_dataframes()

    def _load_dataframes(self):
        """Recursively iterate CSV files inside 'data' folders and store data as pandas dataframes.

        Files will be loaded as pandas dataframes and stored inside a dictionary that
        looks like this: self.dataframes[type of data][node name][file name].
        When a file is found, it is only parsed if listed in self.files_to_load.
        """
        node_file_regex = compile(r'.*/(master|worker_[\d]+)/.*/(.*)/(.*).csv')

        for csv in glob(join(self.artifacts_path, '*', '*', '*', '*.csv')):
            names = node_file_regex.search(csv)
            if names.group(3) in self.files_to_load:
                self.dataframes[names.group(2)][names.group(1)].update({names.group(3): pd.read_csv(csv)})

    def get_setup_phase(self, node_name):
        """Determine when the setup phase begins and ends.

        Args:
            node_name (str): name of the node whose phase should be calculated.

        Returns:
            tuple: start date, end date.
        """
        sync_df = self.dataframes['logs'][node_name]['integrity_sync']['Timestamp']
        return sync_df[0], sync_df[len(sync_df) - 1 if len(sync_df) > 1 else 1]

    def _trim_dataframe(self, df, phase, setup_datetime):
        """Get the dataframe between two datetime.

        Args:
            df (dataframe): original dataframe from which a subset will be obtained.
            phase (str): name of the phase which data should be obtained.
            setup_datetime (tuple): start and end datetime of the setup phase.

        Returns:
            dataframe: subset of data between the dates chosen, according to the phase.
        """
        if phase == self.SETUP_PHASE:
            return df[(df['Timestamp'] >= setup_datetime[0]) & (df['Timestamp'] <= setup_datetime[1])]
        else:
            return df[(df['Timestamp'] > setup_datetime[1])]

    def _calculate_stats(self, df):
        """Calculate statistics from a dataframe.

        Args:
            df (dataframe): dataframe used to obtain stats.

        Raises:
            NotImplementedError: should be implemented in child classes.
        """
        raise NotImplementedError

    def _calculate_all_df_stats(self, dfs_dict):
        """Iterate all dataframes and obtain statistics for each one.

        Args:
            dfs_dict (dict): dict with dataframes to obtain stats from.

        Returns:
            defaultdict: dictionary with stats from each dataframe.
        """
        result = defaultdict(lambda: defaultdict(dict))
        setup_datetime = self.get_setup_phase('master')

        for node, files in dfs_dict.items():
            if all("Daemon" in df for df in files.values()):
                # Ensure these dataframes contain resources' stats before trying to add up all children.
                files = self._add_child_process_to_parent_process(files)

            for phase in [self.SETUP_PHASE, self.STABLE_PHASE]:
                for file_name, file_df in files.items():
                    trimmed_df = self._trim_dataframe(file_df, phase, setup_datetime)
                    if len(trimmed_df) and not (phase == self.STABLE_PHASE and file_name == 'integrity_sync'):
                        result[phase][file_name][node] = self._calculate_stats(trimmed_df)

        return result

    @staticmethod
    def _add_child_process_to_parent_process(files):
        """Add the parent and children processes using the timestamp.

        Args:
            files (dataframe): dataframes to sum up.

        Returns:
            (dict): dictionary that contains a dataframe with all the final results from adding the different processes
            values.
        """
        concat_dfs = pd.concat([file_df for _, file_df in files.items()])
        concat_dfs = concat_dfs.groupby(concat_dfs["Timestamp"]).aggregate(aggregation_function)
        concat_dfs["Daemon"] = concat_dfs["Daemon"].apply(lambda x: "wazuh-clusterd")
        concat_dfs.reset_index(inplace=True)
        return {'wazuh-clusterd': concat_dfs}

    def _group_stats(self, dfs_dict):
        """Group statistics by type of node, phase and column and get the maximum of each group.

        Args:
            dfs_dict (dict): dict with dataframes to obtain stats from.

        Returns:
            defaultdict: Maximum value for each phase, task, type of node (worker/master) and stat.
        """
        nodes_stats = self._calculate_all_df_stats(dfs_dict)
        grouped_data = defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: defaultdict(
            tuple)))))

        for phase, files in nodes_stats.items():
            for file, nodes in files.items():
                for node, columns in nodes.items():
                    for column, stats in columns.items():
                        for stat, value in stats.items():
                            if node == 'master':
                                grouped_data[phase][file][column][node][stat] = (node, value)
                            else:
                                if not grouped_data[phase][file][column]['workers'][stat] or \
                                        grouped_data[phase][file][column]['workers'][stat][1] < value:
                                    grouped_data[phase][file][column]['workers'][stat] = (node, value)

        return grouped_data

    def get_stats(self):
        """Get max stats after grouping by phase, task, type of node and stat.

        Raises:
            NotImplementedError: should be implemented in child classes.
        """
        raise NotImplementedError

    @staticmethod
    def default_to_dict(default_dict):
        """Convert defaultdict to dict."""
        if isinstance(default_dict, defaultdict):
            default_dict = {k: ClusterCSVParser.default_to_dict(v) for k, v in default_dict.items()}

        return default_dict


class ClusterCSVTasksParser(ClusterCSVParser):
    """Class to load, parse CSVs and obtain stats of cluster tasks.

    Args:
        artifacts_path (str): directory where the cluster CSVs can be found.

    Attributes:
        artifacts_path (str): directory where the cluster CSVs can be found.
    """

    def __init__(self, artifacts_path):
        super().__init__(artifacts_path, files_to_load=['integrity_check', 'integrity_sync', 'agent-info_sync'])

    def _calculate_stats(self, df):
        """Calculate mean of 'time_spent(s)' column from a dataframe.

        Args:
            df (dataframe): dataframe to obtain the mean value from.

        Returns:
            dict: mean value for 'time_spent(s)' column.
        """
        return {'time_spent(s)': {'mean': df['time_spent(s)'].mean(),
                                  'max': df['time_spent(s)'].max()}}

    def get_stats(self):
        """Get max stats after grouping by phase, task, type of node and stat.

        Returns:
            dict: max stats obtained from cluster tasks.
        """
        return self.default_to_dict(self._group_stats(self.dataframes['logs']))


class ClusterCSVResourcesParser(ClusterCSVParser):
    """Class to load, parse CSVs and obtain stats of resources used by the 'wazuh-clusterd' process.

    Args:
        artifacts_path (str): directory where the cluster CSVs can be found.
        columns (list, optional): columns of the CSVs to obtain stats from.

    Attributes:
        artifacts_path (str): directory where the cluster CSVs can be found.
        columns (list): columns of the CSVs to obtain stats from.
    """

    def __init__(self, artifacts_path, columns=None):
        self.columns = ['USS(KB)', 'CPU(%)', 'FD'] if columns is None else columns
        super().__init__(artifacts_path, files_to_load=['wazuh_clusterd', 'integrity_sync', 'wazuh_clusterd_child_1',
                                                        'wazuh_clusterd_child_2'])

    def _calculate_stats(self, df):
        """Calculate mean and regression coefficient of each column in self.columns from a dataframe.

        Args:
            df (dataframe): dataframe to obtain the stats from.

        Returns:
            dict: stats for each column.
        """
        result = {}
        for column in self.columns:
            result[column] = {'mean': df[column].mean(),
                              'max': df[column].max(),
                              'reg_cof': np.polyfit(range(len(df)), list(df[column]), 1)[0]}

        return result

    def get_stats(self):
        """Get max stats after grouping by phase, task, type of node and stat.

        Returns:
            dict: max stats obtained from cluster resources.
        """
        return self.default_to_dict(self._group_stats(self.dataframes['binaries']))


class ClusterEnvInfo:
    """Class to obtain information from cluster artifacts files.

    Args:
        artifacts_path (str): directory where the cluster data (nodes, logs, CSVs, etc.) can be found.

    Attributes:
        artifacts_path (str): directory where the cluster data (nodes, logs, CSVs, etc.) can be found.
    """

    def __init__(self, artifacts_path):
        self.artifacts_path = artifacts_path

    def get_file_timestamps(self, node='master', file='integrity_sync.csv'):
        """Get first and last datetime of lines inside a specific file.

        Args:
            node (str): node folder from which the information should be retrieved.
            file (str): filename in any nested level inside 'node' from which the information should be retrieved.

        Returns:
            list: first and last datetime found.
        """
        result = []
        node_file_regex = compile(r'(\d\d\d\d/\d\d/\d\d \d\d:\d\d:\d\d).*')

        with open(next(Path(join(self.artifacts_path, node)).rglob(file), '')) as f:
            data = f.readlines()
            result.extend(node_file_regex.findall(data[1]))
            result.extend(node_file_regex.findall(data[-1]))

        return result

    def count_workers_nodes(self):
        """Count how many worker folders there are in the artifacts.

        Returns:
            int: number of workers in the cluster artifacts.
        """
        return len(glob(join(self.artifacts_path, 'worker_*')))

    def get_phases(self):
        """Get start and end datetime for setup and stable phases.

        Returns:
            dict: start and end datetime for setup and stable phases.
        """
        setup_phase = self.get_file_timestamps()
        stable_phase = [setup_phase[1], self.get_file_timestamps(file='integrity_check.csv')[1]]

        return {'setup_phase': setup_phase, 'stable_phase': stable_phase}

    def get_all_info(self):
        """Get all info from cluster artifacts.

        Returns:
            dict: start and end datetime for each phase and number of workers.
        """
        return {'phases': self.get_phases(), 'worker_nodes': self.count_workers_nodes()}
