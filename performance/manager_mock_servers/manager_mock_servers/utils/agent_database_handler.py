# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
"""This module provides functions to interact with an SQLite database for managing agents.

Functions:
- check_if_agent_exists(database_path, agent_name): Checks if an agent with the given name exists in the database.
- insert_new_agent(database_path, uuid, key, name): Inserts a new agent with the provided UUID, credential, and name into the database.
"""

import sqlite3


def check_if_agent_exists(database_path, agent_name):
    """
    Check if an agent with the specified name exists in the database.

    Args:
        database_path (str): The file path to the SQLite database.
        agent_name (str): The name of the agent to check for.

    Returns:
        tuple or None: A tuple representing the agent record if it exists, otherwise None.
    """
    with sqlite3.connect(database_path) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM agents WHERE name = ?', (agent_name,))
        existing_agent = cursor.fetchone()

    return existing_agent



def check_if_uuid_exists(database_path, uuid):
    """Check if an agent with the specified uuid exists in the database.

    Args:
        database_path (str): The file path to the SQLite database.
        uuid (str): The uuid of the agent to check for.

    Returns:
        tuple or None: A tuple representing the agent record if it exists, otherwise None.
    """
    with sqlite3.connect(database_path) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM agents WHERE uuid = ?', (uuid,))
        existing_agent = cursor.fetchone()

    return existing_agent


def insert_new_agent(database_path, uuid, key, name):
    """
    Insert a new agent into the database.

    Args:
        database_path (str): The file path to the SQLite database.
        uuid (str): The unique identifier for the agent.
        key (str): The credential or key for the agent.
        name (str): The name of the agent.

    Returns:
        None
    """
    with sqlite3.connect(database_path) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO agents (uuid, credential, name)
            VALUES (?, ?, ?)
        ''', (str(uuid), key, name))
        conn.commit()
