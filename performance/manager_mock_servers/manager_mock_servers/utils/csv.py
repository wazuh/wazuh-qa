# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
"""CSV Report Utility Module

This module provides utility functions for initializing and writing data to CSV files.
It includes functions to set up CSV headers and to append data entries with timestamps.

Functions:
    - `init_csv_header(report_path, csv_header_fields)`: Initializes a CSV file with the specified header fields.
    - `write_row_to_csv(report_path, data)`: Appends a row of data to an existing CSV file, including a timestamp.
"""
import csv
from datetime import datetime


def init_csv_header(report_path: str, csv_header_fields: str) -> None:
    """Initializes a CSV file with specified header fields.

    This function creates a new CSV file (or overwrites an existing one) and writes
    the given header fields as the first row of the file.

    Args:
        report_path (str): The path to the CSV file to be created or overwritten.
        csv_header_fields (list): A list of strings representing the header fields for the CSV file.

    Returns:
        None
    """
    with open(report_path, mode='w+', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(csv_header_fields)


def write_row_to_csv(report_path: str, row: list) -> None:
    """Appends a row of data to an existing CSV file with a timestamp.

    This function adds a new row of data to the CSV file specified by `report_path`,
    including a timestamp in the UTC ISO format as the first element of the row.

    Args:
        report_path (str): The path to the CSV file to which data will be appended.
        data (list): A list of values to be written as a new row in the CSV file.

    Returns:
        None
    """
    measurement_datetime = datetime.utcnow().isoformat()

    with open(report_path, mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(row)
