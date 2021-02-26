# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import functools
import sqlite3
import logging

from wazuh_testing.tools import WAZUH_PATH
from wazuh_testing.tools.services import control_service

GLOBAL_DB_PATH = f"{WAZUH_PATH}/queue/db/global.db"


def callback_wazuhdb_response(item):
    if isinstance(item, tuple):
        data, response = item
        return response.decode()


def mock_db(func):
    """Decorator used in any function that needs to mock a wazuh db

    This function will execute `func` after stopping wazuh-modulesd and wazuh-db. After that,
    it will start the daemons again

    Args:
         func (callable): function that will mock the cve.db

    Example:
        @vd.mock__db
        def mock_agent_status(request, agent_id, agent_status):
    """
    @functools.wraps(func)
    def magic(*args, **kwargs):
        control_service('stop', daemon='wazuh-modulesd')
        control_service('stop', daemon='wazuh-db')
        func(*args, **kwargs)
        control_service('start', daemon='wazuh-db')
        control_service('start', daemon='wazuh-modulesd')

    return magic


def mock_agent(agent_id, name="centos8-agent", ip="127.0.0.1", register_ip="127.0.0.1", internal_key="",
                     os_name="CentOS Linux", os_version="7.1", os_major="7", os_minor="1", os_codename="centos-8",
                     os_build="4.18.0-147.8.1.el8_1.x86_64", os_platform="#1 SMP Thu Apr 9 13:49:54 UTC 2020",
                     os_uname="x86_64", os_arch="x86_64", version="4.2", config_sum="", merged_sum="",
                     manager_host="centos-8", node_name="node01", date_add="1612942494",
                     last_keepalive="253402300799", group="", sync_status="synced", connection_status="active",
                     client_key_secret=None):
    create_agent_query = f'''INSERT INTO AGENT
                   (id, name, ip, register_ip, internal_key, os_name, os_version, os_major, os_minor,
                    os_codename, os_build, os_platform, os_uname, os_arch, version, config_sum, merged_sum,
                    manager_host, node_name, date_add, last_keepalive, "group", sync_status, connection_status)
                   VALUES
                   ( {agent_id}, "{name}", "{ip}", "{register_ip}", "{internal_key}", "{os_name}", "{os_version}",
                     "{os_major}", "{os_minor}", "{os_codename}", "{os_build}", "{os_platform}", "{os_uname}",
                     "{os_arch}", "{version}", "{config_sum}", "{merged_sum}", "{manager_host}", "{node_name}",
                     "{date_add}", "{last_keepalive}", "{group}", "{sync_status}", "{connection_status}")
                   '''
    try:
        run_query(create_agent_query, GLOBAL_DB_PATH)
    except sqlite3.IntegrityError:
        logging.error("Failed to mock agent in database!")


def load_db(db_path):
    """Load a database in db_path

    Args:
        db_path (str): path to the database
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    return conn, cursor


@mock_db
def run_query(db_query, db_path=GLOBAL_DB_PATH):
    """Method used to run sqlite queries on wazuh databases

    This function will execute the sqlite3 query `db_query` in `db_path` database.

    Args:
         db_query (string): sqlite3 valid query
         db_path (string): path to the database where the query will be run
    """

    conn, _ = load_db(db_path)

    try:
        with conn:
            conn.execute(db_query)
    finally:
        conn.close()


def get_query_result(query, db_path=GLOBAL_DB_PATH):
    """Return the result of a query in a specified DB

    Args:
        db_path (str): path to the database
        query (str): SQL query. (SELECT * ..)

    Returns:
        result (List[list]): each row is the query result row and each column is the query field value
    """
    global cursor, db
    try:
        db, cursor = load_db(db_path)
        cursor.execute(query)
        records = cursor.fetchall()
        result = []

        for row in records:
            result.append(', '.join([f'{item}' for item in row]))

        return result

    finally:
        cursor.close()
        db.close()
