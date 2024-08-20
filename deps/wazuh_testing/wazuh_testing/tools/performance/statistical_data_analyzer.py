# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import yaml
import pandas as pd

from prettytable import PrettyTable
from collections.abc import Callable
from typing import Any
from scipy.stats import ttest_ind, levene, f_oneway


class DataLoader:
    """Class that validates and loads in the variables all the necessary data for the execution
    of the module. The CSV files that are saved in this class must contain different columns
    that collect the data of the different metrics analyzed. The names of these columns must be
    the names of the metrics in question. In addition, it must contain another column with the
    process or processes to be analyzed. The names of these columns must match those specified
    in the incoming YML file.

    Attributes:
        baseline_path: path to the CSV file containing the baseline data.
        datasource_path: path to the CSV file containing the data to be compared.
        items_path: path to the YML file containing the processes, metrics, and statistics
        to be analyzed.
        baseline: Dataframe generated from the file in baseline_path.
        datasource: Dataframe generated from the file in datasource_path.
        process_name: name of the process to be analyzed. This will be the name of the related
        CSV file column. It must be specified in the items_path file.
        processes: the different processes included in the 'process_name' column of the CSV.
        They can be several or just one.
        metrics: metrics to be analyzed. These must be specified in the file items_path.
    """

    def __init__(self, baseline_path: str, datasource_path: str, items_path: str) -> None:
        """Initializes the DataLoader.

        Args:
            baseline_path (str): path to the CSV file containing the baseline data.
            datasource_path (str): path to the CSV file containing the data to be compared.
            items_path (str): path to the YML file containing the processes, metrics, and statistics
            to be analyzed.
        """
        self.baseline_path = baseline_path
        self.datasource_path = datasource_path
        self.items_path = items_path
        self.validate_paths()
        self.baseline = self.load_dataframe(baseline_path)
        self.datasource = self.load_dataframe(datasource_path)
        self.process_name, self.processes, self.metrics = self.load_yaml_items(self.items_path)

    def validate_paths(self) -> None:
        """Validates the existence of the files used by the module."""
        if not os.path.exists(self.baseline_path) or not os.path.exists(self.datasource_path):
            raise ValueError(f"One or both of the provided CSV files do not exist")

        if not os.path.exists(self.items_path):
            raise ValueError(f"The YML file does not exit")

    def load_dataframe(self, csv_path: str) -> pd.DataFrame:
        """Read the CSV and convert it to dataframe. Also check that the format is valid (CSV)
        and that the file is not empty.

        Args:
            csv_path (str): path to the CSV file to be converted in Dataframe.

        Returns:
            dataframe (pd.Dataframe): Dataframe corresponding to the CSV.
        """
        dataframe = pd.read_csv(csv_path)
        if len(dataframe) == 0:
            raise ValueError(f"The file {csv_path} has not data rows or it has not CSV format")

        return dataframe

    def load_yaml_items(self, yaml_path: str) -> tuple[str, list[str], dict[str, str]]:
        """Process the YML file containing the elements to be analyzed during the test. In addition,
        it obtains from this file the attributes of 'process_name', 'processes' and 'metrics'.

        Args:
            yaml_path (str): path to the YML file containing the elements to be analyzed.

        Returns:
            process_name (str): name of the process to be analyzed.
            processes (list[str]): the different processes that are included in the 'process_name'.
            metrics (dict[str, str]): metrics to be analyzed.
        """
        with open(yaml_path, 'r') as file:
            config = yaml.safe_load(file)

        processes_section = config.get('Processes', {})
        process_name = list(processes_section.keys())[0]
        processes = processes_section[process_name]
        metrics = config.get('Metrics', {})

        return process_name, processes, metrics

    def print_dataframes_stats(self) -> str:
        """Generate a PrettyTable with the statistics for each process and metric.

        Returns:
            output (str): String containing the comparative table.
        """
        output = ""

        for process in self.processes:
            baseline_data = self.baseline[self.baseline[self.process_name] == process]
            datasource_data = self.datasource[self.datasource[self.process_name] == process]

            for metric in self.metrics:
                table = PrettyTable()
                table.title = process + " - " + metric
                table.field_names = ['Name', 'Mean', 'Max value', 'Min value', 'Standard deviation', 'Variance']
                table.add_row([
                    "Baseline",
                    round(baseline_data[metric].mean(), 2),
                    baseline_data[metric].max(), baseline_data[metric].min(),
                    round(baseline_data[metric].std(), 2),
                    round(baseline_data[metric].var(), 2)
                ])
                table.add_row([
                    "Data source",
                    round(datasource_data[metric].mean(), 2),
                    datasource_data[metric].max(), datasource_data[metric].min(),
                    round(datasource_data[metric].std(), 2),
                    round(datasource_data[metric].var(), 2)
                ])
                output += table.get_string() + "\n\n"

        return output


class StatisticalComparator:
    """Class that contains the necessary methods to perform a comparison between the statistics
    of a certain process and a metric. The comparison is made around a threshold value which is
    set in the YML file.
    """

    def calculate_basic_statistics(self, dataframe: pd.DataFrame, metric: str, stat: str) -> float:
        """Calculates the basic statistic of a data set for a specific metric.

        Args:
            dataframe (pd.DataFrame): Dataframe containing the specific data for the calculation.
            metric (str): Metrics on which the statistic will be calculated.
            stat (str): statistics to be calculated.

        Returns:
            value (float): value of the calculated statistic.
        """
        value = 0
        if stat == 'Mean':
            value = round(float(dataframe[metric].mean()), 2)
        elif stat == 'Median':
            value = round(float(dataframe[metric].median()), 2)
        elif stat == 'Max value':
            value = round(float(dataframe[metric].max()), 2)
        elif stat == 'Min value':
            value = round(float(dataframe[metric].min()), 2)
        elif stat == 'Standard deviation':
            value = round(float(dataframe[metric].std()), 2)
        elif stat == 'Variance':
            value = round(float(dataframe[metric].var()), 2)

        return value

    def comparison_basic_statistics(self, baseline : pd.DataFrame, datasource: pd.DataFrame, metric: str,
                                    stat: str, threshold: float) -> int:
        """Compares the percent change in a statistic between the two data sets to determine
        if there is a significant change based on the threshold value.

        Args:
            baseline (pd.DataFrame): Dataframe with the baseline data.
            datasource (pd.DataFrame): Dataframe with the incoming data source.
            metric (str): metric from which the statistic to be compared are obtained.
            stat (str): concrete statistic to be compared.
            threshold (float): threshold for comparison.

        Returns:
            discrepancie (int): if the percentage difference is greater than the threshold,
            it returns 1, otherwise it returns 0.
        """
        discrepancy = 0
        baseline_value = self.calculate_basic_statistics(baseline, metric, stat)
        dataframe_value = self.calculate_basic_statistics(datasource, metric, stat)

        if baseline_value != 0:
            diff = abs(baseline_value - dataframe_value) / baseline_value
        else:
            diff = abs(baseline_value - dataframe_value)

        if diff >= threshold:
            discrepancy = 1

        return discrepancy


class StatisticalTests:
    """Class responsible for performing statistical tests on two sets of data, which allows
    to detect significant differences between them.
    """

    def perform_test(self, baseline: pd.DataFrame, datasource: pd.DataFrame, metric: str,
                     test_func: Callable[..., float], **args: Any) -> float:
        """A general method that performs a statistical test on two sets of data.

        Args:
            baseline (pd.DataFrame): Dataframe with the baseline data.
            datasource (pd.DataFrame): Dataframe with the incoming data source.
            metric (str): metric on which the test is performed.
            test_func (Callable[..., float]): the function of the statistical test to be executed.
            args (Any): additional arguments for the test function.

        Returns:
            p_value (float): p value of the statistical test performed.
        """
        baseline_values = baseline[metric].dropna()
        datasource_values = datasource[metric].dropna()

        _, p_value = test_func(baseline_values, datasource_values, **args)

        return p_value

    def t_student_test(self, baseline: pd.DataFrame, datasource: pd.DataFrame, metric: str) -> float:
        """Performs the statistical analysis using the t-student test.

        Args:
            baseline (pd.DataFrame): Dataframe with the baseline data.
            datasource (pd.DataFrame): Dataframe with the incoming data source.
            metric (str): metric on which the test is performed

        Returns:
            (float): p value returned by the t-student test.
        """
        return self.perform_test(baseline, datasource, metric, ttest_ind, equal_var=False)

    def t_levene_test(self, baseline: pd.DataFrame, datasource: pd.DataFrame, metric: str) -> float:
        """Performs the statistical analysis using the Levene test.

        Args:
            baseline (pd.DataFrame): Dataframe with the baseline data.
            datasource (pd.DataFrame): Dataframe with the incoming data source.
            metric (str): metric on which the test is performed.

        Returns:
            (float): p value returned by the Levene test.
        """
        return self.perform_test(baseline, datasource, metric, levene)

    def t_anova_test(self, baseline: pd.DataFrame, datasource: pd.DataFrame, metric: str) -> float:
        """Performs the statistical analysis using the ANOVA test.

        Args:
            baseline (pd.DataFrame): Dataframe with the baseline data.
            datasource (pd.DataFrame): Dataframe with the incoming data source.
            metric (str): metric on which the test is performed.

        Returns:
            (float): p value returned by the ANOVA test.
        """
        return self.perform_test(baseline, datasource, metric, f_oneway)
