# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

"""Statistical Data Analyzer Module Test.

This module contains a basic test that allows you to perform statistical analysis and calculations
on two data sets and to make comparisons between them. This allows to detect significant
differences between the two sets automatically.

This test uses t-Student, Levene and ANOVA tests to detect possible significant differences in the
metrics of the data sets. If such differences exist, comparisons are made between the main
statistics with respect to a threshold value which, if exceeded, is marked as an error and
reported conveniently.

Tests:
    - test_comparison: detects significant differences between metrics of two data sets.

Issue: https://github.com/wazuh/wazuh/issues/24688
"""

import logging
from collections.abc import Callable
from typing import Tuple

import pytest
import yaml
from _pytest.python import Metafunc
from statistical_data_analyzer import DataLoader, StatisticalComparator, StatisticalTests


# Configure logging
logging.basicConfig(level=logging.INFO)


def pytest_generate_tests(metafunc: Metafunc) -> None:
    """Hook to generate test parameters based on the YML file content.

    Args:
        metafunc (Metafunc): Metafunc object that contains information about the test.
    """
    if "metric" in metafunc.fixturenames:
        config_file = metafunc.config.getoption("--items_yaml")

        with open(config_file) as file:
            config_data = yaml.safe_load(file)

        metrics = list(config_data.get('Metrics', {}).keys())

        metafunc.parametrize("metric", metrics)


def test_comparison(get_data: Callable[[], Tuple[str, str, float]], get_comparison_config: Callable[[], str],
                    metric: str) -> None:
    """Detect significant differences and compare the statistics.

    Description:
        It checks if any statistical test detects significant changes and if so, compares the statistics
        of both data sets to detect changes with respect to a threshold value.

    Args:
        get_data (Callable[[], tuple[str, str, float]]): fixture that contains baseline, incoming data
        source Dataframes, and the confidence level values.
        get_comparison_config (Callable[[], str]): fixture that contains the YML file with the items to be analyzed.
        metric (str): metric to be analyzed by the test, obtained from the parameterization.
    """
    baseline_file, datasource_file, confidence_level = get_data
    config_file = get_comparison_config
    data = DataLoader(baseline_file, datasource_file, config_file)
    stats_comp = StatisticalComparator()
    stats_tests = StatisticalTests()

    errors = []
    p_values = []
    p_value = (100 - confidence_level) / 100

    for process in data.processes:
        baseline_data = data.baseline[data.baseline[data.process_name] == process]
        datasource_data = data.datasource[data.datasource[data.process_name] == process]

        stats = data.metrics[metric]

        t_p_value = stats_tests.t_student_test(baseline_data, datasource_data, metric)
        l_p_value = stats_tests.t_levene_test(baseline_data, datasource_data, metric)
        a_p_value = stats_tests.t_anova_test(baseline_data, datasource_data, metric)

        if t_p_value < p_value or l_p_value < p_value or a_p_value < p_value:
            for stat, threshold_value in stats.items():
                threshold_value = threshold_value / 100
                try:
                    assert stats_comp.comparison_basic_statistics(baseline_data, datasource_data,
                                                                    metric, stat, threshold_value) != 1
                except AssertionError:
                    errors.append(f"Difference over {threshold_value*100}% detected in '{process}'" +
                                    f" - '{metric}' - '{stat}'. t_student p-value: {t_p_value}, " +
                                    f"levene p-value: {l_p_value}, anova p-value: {a_p_value}")
        else:
           p_values.append(f"t_student p-value: {t_p_value}, " f"levene p-value: {l_p_value}, " +
                           f"anova p-value: {a_p_value}")

    if errors:
        pytest.fail("\n".join(errors))
    else:
        logging.info(f"P-values for metric '{metric}':")
        logging.info("\n".join(p_values))
