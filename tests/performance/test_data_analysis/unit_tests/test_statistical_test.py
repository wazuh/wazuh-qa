# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

"""Unit tests for the StatisticalTests class"""

import pytest
import pandas as pd

from statistical_data_analyzer import StatisticalTests


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
def sample_data2() -> None:
    """Fixture that returns a DataFrame for the second data set.

    Returns:
        (pd.Dataframe): Dataframe with the second data.
    """
    data = {
        'Metric1': [100, 200, 300, 400],
        'Metric2': [1000, 2000, 3000, 4000]
    }
    return pd.DataFrame(data)

def test_t_student_test(sample_data1: pd.DataFrame, sample_data2: pd.DataFrame) -> None:
    """Test that checks the accuracy of the t_student test function.

    Args:
        sample_data1 (pd.Dataframe): first Dataframe.
        sample_data2 (pd.Dataframe): second Dataframe.
    """
    stats_tests = StatisticalTests()
    p_value = stats_tests.t_student_test(sample_data1, sample_data1, 'Metric1')
    assert p_value == 1.0
    p_value = stats_tests.t_student_test(sample_data1, sample_data2, 'Metric2')
    assert p_value < 0.95

def test_levene_test(sample_data1: pd.DataFrame, sample_data2: pd.DataFrame) -> None:
    """Test that checks the accuracy of the Levene test function.

    Args:
        sample_data1 (pd.Dataframe): first Dataframe.
        sample_data2 (pd.Dataframe): second Dataframe.
    """
    stats_tests = StatisticalTests()
    p_value = stats_tests.t_levene_test(sample_data1, sample_data1, 'Metric1')
    assert p_value == 1.0
    p_value = stats_tests.t_levene_test(sample_data1, sample_data2, 'Metric2')
    assert p_value < 0.95

def test_anova_test(sample_data1: pd.DataFrame, sample_data2: pd.DataFrame) -> None:
    """Test that checks the accuracy of the ANOVA test function.

    Args:
        sample_data1 (pd.Dataframe): first Dataframe.
        sample_data2 (pd.Dataframe): second Dataframe.
    """
    stats_tests = StatisticalTests()
    p_value = stats_tests.t_anova_test(sample_data1, sample_data1, 'Metric1')
    assert p_value == 1.0
    p_value = stats_tests.t_anova_test(sample_data1, sample_data2, 'Metric2')
    assert p_value < 0.95
