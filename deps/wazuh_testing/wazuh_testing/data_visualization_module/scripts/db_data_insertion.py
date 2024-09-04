# Copyright (C) 2024, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

"""Script that inserts data from CSV files into the database."""

import os
from typing import Tuple

import argparse
import glob
import sqlite3


# Name of the SQLite database file
database_file = "../data/data.db"

def get_arguments() -> Tuple[str, str]:
    """Function that receives and returns the script parameters.

    Returns:
        Tuple[str, str]: the directory path and component.
    """
    parser = argparse.ArgumentParser(
        usage='%(prog)s [directory] [componet]',
        description='Script to Load CSV Files to a Database',
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument(
        "directory", type=str, help="Path to the directory containing CSV files."
    )

    parser.add_argument(
        "component", type=str, help="Name of the Wazuh component to which the CSV files belong."
    )

    args = parser.parse_args()

    return args.directory, args.component


def validate_arguments(directory: str, component: str) -> None:
    """Validates that the directory exists and contains CSV files, and the component string.

    Args:
        directory (str): the path to the directory.
        component (str): the Wazuh component
    """
    if not os.path.isdir(directory):
        raise ValueError(f"Directory '{directory}' does not exist.")

    csv_files = glob.glob(os.path.join(directory, "*.csv"))
    if not csv_files:
        raise ValueError(f"No CSV files found in directory '{directory}'.")

    valid_components = {"agent", "dashboard", "manager", "indexer"}
    if component.lower() not in valid_components:
        raise ValueError(f"Invalid component '{component}'.")


def load_csv_files_to_db(directory: str, component: str, conn: sqlite3.Connection) -> None:
    """Loads CSV files from a directory into a database.

    Args:
        directory (str): Path to the directory containing CSV files.
        component (str): Component name to associate with the files.
        conn (sqlite3.Connection): SQLite database connection.
    """
    files = glob.glob(os.path.join(directory, "*.csv"))

    print("Inserting data into the database...")

    for file in files:
        filename = os.path.basename(file)
        with open(file, 'rb') as f:
            file_content = f.read()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR IGNORE INTO file_storage (filename, file_content, component) VALUES (?, ?, ?)",
            (filename, file_content, component)
        )
        conn.commit()
    
    print("\nAll data have been inserted.")


def create_table(conn: sqlite3.Connection) -> None:
    """Function that creates the database table.

    Args:
        conn (sqlite3.Connection): SQLite database connection.
    """
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS file_storage (
        file_id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT UNIQUE,
        file_content BLOB,
        component TEXT
    )
    ''')
    conn.commit()


def main() -> None:
    """Main function that executes the script."""
    # Get arguments
    directory, component = get_arguments()

    # Validate input arguments
    validate_arguments(directory, component)

    # Connect to the database and create table
    conn = sqlite3.connect(database_file)
    create_table(conn)

    # Load CSV files into the database
    load_csv_files_to_db(directory, component, conn)

    # Close the database connection
    conn.close()


if __name__ == "__main__":
    main()
