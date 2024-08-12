# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
"""Tests for CSV module."""
import csv
import os
from typing import Generator

import pytest
from _pytest.tmpdir import TempPathFactory

from utils.csv import init_csv_header, write_row_to_csv


@pytest.fixture
def csv_file(tmp_path_factory: TempPathFactory) -> Generator:
    """Fixture that provides a temporary CSV file for testing.

    The file's path is returned to be used in tests to ensure no actual files are modified
    during testing.

    Yield:
        str: Path to the temporary CSV file.
    """
    temporal_dir = tmp_path_factory.mktemp('metrics')

    yield os.path.join(temporal_dir, 'test_report.csv')


def test_init_csv_header(csv_file: str):
    """Test that the CSV header is initialized correctly.

    This test verifies that the `init_csv_header` function correctly writes the specified
    headers to the CSV file. After calling `init_csv_header`, the test reads the first row
    of the CSV file to ensure it matches the expected headers.

    Args:
        csv_file (str): Path to the temporary CSV file created by the fixture.

    Assertions:
        Asserts that the first row in the CSV file matches the specified headers.
    """
    headers = ["Date", "Count"]
    init_csv_header(str(csv_file), headers)

    with open(str(csv_file)) as file:
        reader = csv.reader(file)
        row = next(reader)
        assert row == headers


def test_write_row_to_csv(csv_file: str):
    """Test that data is appended correctly to the CSV file.

    This test checks that the `write_row_to_csv` function appends data rows to the CSV file
    after initializing it with a header. The test first sets up the CSV file with headers,
    then writes a data row, and finally reads the file to verify that both the header and
    data row are present and correct.

    Args:
        csv_file (str): Path to the temporary CSV file created by the fixture.

    Assertions:
        - Asserts that the header is correctly written as the first row.
        - Asserts that the data row is correctly appended as the second row.
        - Confirms that there are exactly two rows in the file: header and data row.
    """
    headers = ["Value1", "Value2"]
    init_csv_header(str(csv_file), headers)

    data = ['3', '5']
    write_row_to_csv(str(csv_file), data)

    with open(str(csv_file)) as file:
        reader = csv.reader(file)
        rows = list(reader)

    assert rows[0] == headers
    assert len(rows) == 2  # Should be 2 rows: header + one data row
    assert rows[1][0:] == data
