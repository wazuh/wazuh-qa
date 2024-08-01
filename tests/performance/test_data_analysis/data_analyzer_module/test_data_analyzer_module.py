# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

"""
Statistical Data Analyzer Module Test
-------------------------------------

Brief:
    This module contains a basic test that allows you to perform statistical analysis and calculations on two data sets and to 
    make comparisons between them. This allows to detect significant differences between the two sets automatically.

    This test uses t-Student, Levene and ANOVA tests to detect possible significant differences in the metrics of the data sets. 
    If such differences exist, comparisons are made between the main statistics with respect to a threshold value which, if 
    exceeded, is marked as an error and reported conveniently.

Tests:
    - test_comparison: detects significant differences between metrics of two data sets

Issue: https://github.com/wazuh/wazuh/issues/24688
"""

import pytest
from wazuh_testing.tools.performance.statistical_data_analyzer import DataLoader, StatisticalComparator, StatisticalTests

def test_comparison(load_data, config):
    """The main test of the module. It checks if any statistical test detects significant changes and if so, 
    compares the statistics of both data sets to detect changes with respect to a threshold value.  

    Args:
        load_data: fixture that contains baseline and data source Dataframes, and the
        threshold and confidence level values.
        config: Dict that contains the items to be analyzed.
    """
    baseline_file, datasource_file, confidence_level = load_data
    config_file = config

    data = DataLoader(baseline_file, datasource_file, config_file)
    stats_comp = StatisticalComparator()
    stats_tests = StatisticalTests()

    errors = []
    p_value = (100 - confidence_level) / 100

    for process in data.processes:
        baseline_data = data.baseline[data.baseline[data.process_name] == process]
        datasource_data = data.datasource[data.datasource[data.process_name] == process]

        for value, stats in data.metrics.items():
            t_p_value =  stats_tests.t_student_test(baseline_data, datasource_data, value)
            l_p_value =  stats_tests.t_levene_test(baseline_data, datasource_data, value)
            a_p_value =  stats_tests.t_anova_test(baseline_data, datasource_data, value)

            if t_p_value < p_value or l_p_value < p_value or a_p_value < p_value:
                for stat, threshold_value in stats.items():
                    threshold_value = threshold_value / 100
                    try:
                        assert stats_comp.comparison_basic_statistics(baseline_data, datasource_data, 
                                                                      value, stat, threshold_value) != 1
                    except AssertionError:
                        errors.append(f"Difference over {threshold_value*100}% detected in '{process}' - '{value}' - '{stat}'")

    if errors:
        pytest.fail("\n".join(errors))
