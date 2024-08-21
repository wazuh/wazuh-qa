# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

"""Unit tests for the DataLoader class"""

import pandas as pd

from statistical_data_analyzer import DataLoader
from pytest_mock import MockerFixture


def test_dataloader_initialization(mocker: MockerFixture) -> None:
    """Test that verifies that the class is initialized correctly and that the
    attributes contain the correct values.

    Args:
        mocker (MockerFixture): mocker to simulate the files.
    """
    mocker.patch("os.path.exists", return_value=True)
    mocker.patch("pandas.read_csv", return_value=pd.DataFrame({"col1": [1, 2], "col2": [3, 4]}))
    mocker.patch("builtins.open", mocker.mock_open(read_data="""
    Processes:
      proc:
        - p1
    Metrics:
      metric1:
        stat1: 5"""))
    mocker.patch("yaml.safe_load", return_value={"Processes": {"proc": ["p1"]},
                                                 "Metrics": {"metric1": {"stat1": 5}}})

    dataloader = DataLoader("baseline.csv", "datasource.csv", "items.yml")

    assert dataloader.baseline_path == "baseline.csv"
    assert dataloader.datasource_path == "datasource.csv"
    assert dataloader.items_path == "items.yml"
    assert not dataloader.baseline.empty
    assert not dataloader.datasource.empty
    assert dataloader.process_name == "proc"
    assert dataloader.processes == ["p1"]
    assert dataloader.metrics == {"metric1": {"stat1": 5}}


def test_load_dataframe(mocker: MockerFixture) -> None:
    """Test to check that when loading a Dataframe, it is not empty and contains the correct information.

    Args:
        mocker (MockerFixture): mocker to simulate the file.
    """
    mocker.patch("os.path.exists", return_value=True)
    mocker.patch("pandas.read_csv", return_value=pd.DataFrame({"col1": [1, 2], "col2": [3, 4]}))
    mocker.patch("builtins.open", mocker.mock_open(read_data="""
    Processes:
      proc:
        - p1
    Metrics:
      metric1:
        stat1: 10"""))
    mocker.patch("yaml.safe_load", return_value={"Processes": {"proc": ["p1"]},
                                                 "Metrics": {"metric1": {"stat1": 10}}})

    dataloader = DataLoader("baseline.csv", "datasource.csv", "items.yml")
    dataframe = dataloader.load_dataframe("baseline.csv")

    assert not dataframe.empty
    assert list(dataframe.columns) == ["col1", "col2"]


def test_load_yaml_items(mocker: MockerFixture) -> None:
    """Test that checks the loading of the data from the YAML file and the correct initialization of the variables.

    Args:
        mocker (MockerFixture): mocker to simulate the file.
    """
    mocker.patch("os.path.exists", return_value=True)
    mocker.patch("builtins.open", mocker.mock_open(read_data="""
    Processes:
      proc:
        - p1
    Metrics:
      metric1:
        stat1: 10"""))
    mocker.patch("yaml.safe_load", return_value={"Processes": {"proc": ["p1"]},
                                                 "Metrics": {"metric1": {"stat1": 10}}})

    dataloader = DataLoader("baseline.csv", "datasource.csv", "items.yml")
    process_name, processes, metrics = dataloader.load_yaml_items("items.yml")

    assert process_name == "proc"
    assert processes == ["p1"]
    assert metrics == {"metric1": {"stat1": 10}}


def test_print_dataframes_stats(mocker: MockerFixture) -> None:
    """Test that checks the correct functioning of the function that displays statistics in tables.

    Args:
        mocker (MockerFixture): mocker to simulate the file.
    """
    mocker.patch("os.path.exists", return_value=True)
    mocker.patch("pandas.read_csv", side_effect=[
        pd.DataFrame({"proc": ["p1"], "metric1": 10, "metric2": 1000}),
        pd.DataFrame({"proc": ["process1"], "metric1": 15, "metric2": 1500})
    ])
    mocker.patch("builtins.open", mocker.mock_open(read_data="""
    Processes:
      proc:
        - p1
    Metrics:
      metric1:
        stat1: 10"""))
    mocker.patch("yaml.safe_load", return_value={"Processes": {"proc": ["p1"]}, "Metrics": {"metric1": {"stat1": 10, "stat2": 100}}})

    dataloader = DataLoader("baseline.csv", "datasource.csv", "items.yml")

    output = dataloader.print_dataframes_stats()

    assert "p1 - metric1" in output
    assert "Baseline" in output
    assert "Data source" in output
