# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from collections import defaultdict
from glob import glob
from os.path import join
from re import compile

import numpy as np
import pandas as pd


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
        looks like this: self.dataframes[type of data (logs/binaries)][node name][file name].
        When a file is found, it is only parsed if listed in self.files_to_load.
        """
        node_file_regex = compile(r'.*/(master|worker_[\d]+)/.*/(.*)/(.*).csv')

        for csv in glob(join(self.artifacts_path, '*', 'data', '*', '*.csv')):
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
        return sync_df[0], sync_df[len(sync_df)-1 if len(sync_df) > 1 else 1]

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

    def _calculate_all_df_stats(self, dict_df):
        """Iterate all dataframes and obtain statistics for each one.

        Args:
            dict_df (dict): dict with dataframes to obtain stats from.

        Returns:
            dict: dictionary with stats from each dataframe.
        """
        result = defaultdict(lambda: defaultdict(dict))

        for node, files in dict_df.items():
            setup_datetime = self.get_setup_phase(node)
            for phase in [self.SETUP_PHASE, self.STABLE_PHASE]:
                for file_name, file_df in files.items():
                    trimmed_df = self._trim_dataframe(file_df, phase, setup_datetime)
                    if len(trimmed_df):
                        result[phase][file_name][node] = self._calculate_stats(trimmed_df)

        return result

    def get_max_stats(self):
        """Group statistics by node, phase and file and get the maximum of each group.

        Raises:
            NotImplementedError: should be implemented in child classes.
        """
        raise NotImplementedError


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
            float: mean value for 'time_spent(s)' column.
        """
        return df['time_spent(s)'].mean()

    def get_max_stats(self):
        """Group statistics by type of node, phase and cluster task and get the maximum of each group.

        Returns:
            dict: Maximum mean value for each phase, task and type of node.
        """
        nodes_stats = self._calculate_all_df_stats(self.dataframes['logs'])
        grouped_data = defaultdict(lambda: defaultdict(lambda: defaultdict(tuple)))

        for phase, tasks in nodes_stats.items():
            for task, nodes in tasks.items():
                for node, mean in nodes.items():
                    if node == 'master':
                        grouped_data[phase][task][node] = (node, mean)
                    else:
                        if not grouped_data[phase][task]['workers'] or grouped_data[phase][task]['workers'][1] < mean:
                            grouped_data[phase][task]['workers'] = (node, mean)

        return grouped_data


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
        if columns is None:
            columns = ['USS(KB)', 'CPU(%)', 'FD']

        self.columns = columns
        super().__init__(artifacts_path, files_to_load=['wazuh-clusterd', 'integrity_sync'])

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
                              'reg_cof': np.polyfit(range(len(df)), list(df[column]), 1)[0]}

        return result

    def get_max_stats(self):
        """Group statistics by type of node, phase and resource/column and get the maximum of each group.

        Returns:
            dict: Maximum value for each phase, task, type of node and stat.
        """
        nodes_stats = self._calculate_all_df_stats(self.dataframes['binaries'])
        grouped_data = defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: defaultdict(
            tuple)))))

        for phase, files in nodes_stats.items():
            for file, nodes in files.items():
                for node, resources in nodes.items():
                    for resource, stats in resources.items():
                        for stat, value in stats.items():
                            if node == 'master':
                                grouped_data[phase][file][resource][node][stat] = (node, value)
                            else:
                                if not grouped_data[phase][file][resource]['workers'][stat] or \
                                        grouped_data[phase][file][resource]['workers'][stat][1] < value:
                                    grouped_data[phase][file][resource]['workers'][stat] = (node, value)

        return grouped_data
