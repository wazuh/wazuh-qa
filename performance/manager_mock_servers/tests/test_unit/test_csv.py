# test_csv_handler.py

import os
import pytest
import csv
from datetime import datetime
from manager_mock_servers.utils.csv import init_csv_header, write_counts_to_csv

@pytest.fixture
def csv_file(tmpdir):
    """Fixture that provides a temporary CSV file for testing."""
    return tmpdir.join("test_report.csv")

def test_init_csv_header(csv_file):
    """Test that the CSV header is initialized correctly."""
    headers = ["Date", "Count"]
    init_csv_header(str(csv_file), headers)

    with open(str(csv_file), mode='r') as file:
        reader = csv.reader(file)
        row = next(reader)
        assert row == headers

def test_write_counts_to_csv(csv_file):
    """Test that data is appended correctly to the CSV file."""
    headers = ["Value1", "Value2"]
    init_csv_header(str(csv_file), headers)

    data = ['3', '5']
    write_counts_to_csv(str(csv_file), data)

    with open(str(csv_file), mode='r') as file:
        reader = csv.reader(file)
        rows = list(reader)

    # Check that the header is the first row
    assert rows[0] == headers

    # Check the data row, which should include a timestamp and data
    assert len(rows) == 2  # Should be 2 rows: header + one data row
    assert rows[1][0:] == data
