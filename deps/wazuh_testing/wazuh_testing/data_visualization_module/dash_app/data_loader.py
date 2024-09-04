# Copyright (C) 2024, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

"""Module that contains the functions necessary to obtain the data to be displayed from the database."""

import io
import pandas as pd
import sqlite3
from typing import Dict, Tuple, Any, List

from cache import cache


# Data base file containing all the information
database_file = "../data/data.db"

def query_db(query:str, params: Tuple[Any, ...] = ()) -> pd.DataFrame:
    """Function that performs a query to the database, and may include parameters.

    Args:
        query (str): string containing the sql query
        params (Tuple[Any, ...]): possible parameters for the database query.

    Returns:
        df (pd.DataFrame): Dataframe with the result of the query.
    """
    conn = sqlite3.connect(database_file)
    df = pd.read_sql_query(query, conn, params=params)
    conn.close()
    return df


def extract_config_parameters(config: Dict[str, Any]) -> Tuple[str, str, List[str]]:
    """Function that extracts the necessary parameters for database queries from the YAML configuration file.

    Args:
        config (Dict[str, Any]): dictionary containing the information from the YAML file.

    Returns:
        component (str): component on which the visualization is to be performed.
        processes (List[str]): process or processes found in the process_name column of the CSV.
        columns_to_avoid (List[str]): columns that you do not want to load in the visualization.
        process_name (str): name of the main process to be displayed.
    """
    component = config.get('Component', [])[0]
    process_name = list(config.get('Processes', {}).keys())[0]
    processes = config.get('Processes', {}).get(process_name, [])
    columns_to_avoid = config.get('Columns_to_avoid', [])

    return component, processes, columns_to_avoid, process_name


def load_initial_data_from_db(config: Dict[str, Any]) -> Tuple[List[str], List[str], Dict[str, str]]:
    """Function that loads data from the database for initial display of it in the application.

    Args:
        config (Dict[str, Any]): dictionary containing the information from the YAML file.

    Returns:
        processes (List[str]): list of processes to display.
        column_names (List[str]): columns in the CSV file to be displayed.
        commit_values (Dict[str, str]): dictionary containing the commit value of each file along with its version.
    """
    component, processes, columns_to_avoid, _ = extract_config_parameters(config)

    query = "SELECT filename, file_content FROM file_storage WHERE component = ?"
    files = query_db(query, (component,))

    if files.empty:
        print("No files found for the specified component.")
        return [], [], {}

    column_names = []
    commit_values = {}

    file_content = io.BytesIO(files.iloc[0]['file_content'])
    df = pd.read_csv(file_content)
    column_names = [col for col in df.columns if col not in columns_to_avoid]

    for _, row in files.iterrows():
        file_content = io.BytesIO(row['file_content'])
        df = pd.read_csv(file_content, usecols=['Version', 'Commit'])
        version = df['Version'].iloc[0]
        commit = df['Commit'].iloc[0]

        if commit not in commit_values:
            commit_values[commit] = []
        commit_values[commit].append(version)

    return processes, column_names, commit_values


@cache.memoize()
def load_csv_files_from_db(processes: List[str], versions: List[str], 
                           component: str, process_name: str) -> pd.DataFrame:
    """Function that queries the database to extract the file to be displayed.

    It also adjusts the information of that file and returns it as a DataFrame for viewing. The seconds_since_start
    column is added for the x-axis visualization and the process_version column is added for the graph legend.
    The file name must be the same as the value in the version column to make the search more efficient.
    For example: 4.8.0-beta4.csv. Uses cache memory to store queries and thus improve efficiency.

    Args:
        processes (List[str]): list of processes to display.
        versions (List[str]): list of versions of the files to display.
        component (str): Wazuh component (agent, manager, etc.).
        process_name (str): name of the main process to be displayed.

    Returns:
        (pd.DataFrame): final DataFrame with the information needed to display it in the graph.
    """
    query = "SELECT filename, file_content FROM file_storage WHERE filename LIKE ? AND component = ?"
    dataframes = []

    for version in versions:
        filename_pattern = f"{version}.csv"
        file = query_db(query, (filename_pattern, component))

        row = file.iloc[0]
        file_content = io.BytesIO(row['file_content'])
        df = pd.read_csv(file_content)
        df['Timestamp'] = pd.to_datetime(df['Timestamp'])
        df['seconds_since_start'] = (df['Timestamp'] - df['Timestamp'].iloc[0]).dt.total_seconds()
        df['process_version'] = df[process_name] + ' ' + df['Version']
        df = df[df[process_name].isin(processes)]
        dataframes.append(df)

    if dataframes:
        combined_df = pd.concat(dataframes, ignore_index=True)
        return combined_df

    return pd.DataFrame()
