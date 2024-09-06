# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

"""Unit tests for the StatisticalComparator class."""

import pandas as pd
import pytest
from statistical_data_analyzer import StatisticalComparator


@pytest.fixture
def sample_data1() -> pd.DataFrame:
    """Fixture that returns a DataFrame for the first data set.

    Returns:
        (pd.Dataframe): Dataframe with the first data.
    """
    data = {
        'Metric1': [10, 20, 30, 40],
        'Metric2': [100, 200, 300, 400]
    }
    return pd.DataFrame(data)


@pytest.fixture
def sample_data2() -> pd.DataFrame:
    """Fixture that returns a DataFrame for the second data set.

    Returns:
        (pd.Dataframe) Dataframe with the second data.
    """
    data = {
        'Metric1': [120, 20, 30, 40],
        'Metric2': [100, 200, 300, 400]
    }
    return pd.DataFrame(data)


def test_calculate_basic_statistics(sample_data1: pd.DataFrame) -> None:
    """Test that checks the accuracy of the statistics calculation.

    Args:
        sample_data1 (pd.Dataframe): first Dataframe.
    """
    comparator = StatisticalComparator()
    mean_value = comparator.calculate_basic_statistics(sample_data1, 'Metric1', 'Mean')
    median_value = comparator.calculate_basic_statistics(sample_data1, 'Metric1', 'Median')
    max_value = comparator.calculate_basic_statistics(sample_data1, 'Metric2', 'Max value')
    min_value = comparator.calculate_basic_statistics(sample_data1, 'Metric2', 'Min value')
    std_value = comparator.calculate_basic_statistics(sample_data1, 'Metric1', 'Standard deviation')
    var_value = comparator.calculate_basic_statistics(sample_data1, 'Metric2', 'Variance')
    assert mean_value == 25
    assert median_value == 25
    assert max_value == 400
    assert min_value == 100
    assert std_value == 12.91
    assert var_value == 16666.67


def test_comparison_basic_statistics(sample_data1: pd.DataFrame, sample_data2: pd.DataFrame) -> None:
    """Test that checks the accuracy of the statistics comparison.

    Args:
        sample_data1 (pd.Dataframe): first Dataframe.
        sample_data2 (pd.Dataframe): second Dataframe.
    """
    comparator = StatisticalComparator()
    mean_discrepancy = comparator.comparison_basic_statistics(sample_data1, sample_data2, 'Metric1', 'Mean', 0.1)
    median_discrepancy = comparator.comparison_basic_statistics(sample_data1, sample_data2, 'Metric1', 'Median', 0.1)
    max_discrepancy = comparator.comparison_basic_statistics(sample_data1, sample_data2, 'Metric1', 'Max value', 0.1)
    min_discrepancy = comparator.comparison_basic_statistics(sample_data1, sample_data2, 'Metric2', 'Min value', 0.1)
    std_discrepancy = comparator.comparison_basic_statistics(sample_data1, sample_data2, 'Metric2',
                                                             'Standard deviation', 0.1)
    var_discrepancy = comparator.comparison_basic_statistics(sample_data1, sample_data2, 'Metric2', 'Variance', 0.1)
    assert mean_discrepancy == 1
    assert median_discrepancy == 1
    assert max_discrepancy == 1
    assert min_discrepancy == 0
    assert std_discrepancy == 0
    assert var_discrepancy == 0
