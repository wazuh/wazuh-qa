# Copyright (C) 2015-2022, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import functools
import hashlib
import json
import logging
import socket
import sqlite3
import time

from wazuh_testing.tools import GLOBAL_DB_PATH, WAZUH_DB_SOCKET_PATH
from wazuh_testing.tools.monitoring import wazuh_pack, wazuh_unpack
from wazuh_testing.tools.services import control_service


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
        func(*args, **kwargs)
        control_service('start', daemon='wazuh-modulesd')

    return magic


def mock_agent(
        agent_id, name="centos8-agent", ip="127.0.0.1", register_ip="127.0.0.1", internal_key="",
        os_name="CentOS Linux", os_version="7.1", os_major="7", os_minor="1", os_codename="centos-8",
        os_build="4.18.0-147.8.1.el8_1.x86_64", os_platform="#1 SMP Thu Apr 9 13:49:54 UTC 2020",
        os_uname="x86_64", os_arch="x86_64", version="4.2", config_sum="", merged_sum="",
        manager_host="centos-8", node_name="node01", date_add="1612942494",
        last_keepalive="253402300799", group="", sync_status="synced", connection_status="active",
        client_key_secret=None):

    create_agent_query = f'''global sql INSERT OR REPLACE INTO AGENT
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
        query_wdb(create_agent_query)
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


def query_wdb(command):
    """Make queries to wazuh-db using the wdb socket.

    Args:
        command (str): wazuh-db command alias. For example `global get-agent-info 000`.

    Returns:
        list: Query response data
    """
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(WAZUH_DB_SOCKET_PATH)

    data = []

    try:
        sock.send(wazuh_pack(len(command)) + command.encode())

        rcv = sock.recv(4)

        if len(rcv) == 4:
            data_len = wazuh_unpack(rcv)

            data = sock.recv(data_len).decode()

            # Remove response header and cast str to list of dictionaries
            # From --> 'ok [ {data1}, {data2}...]' To--> [ {data1}, data2}...]
            if len(data.split()) > 1 and data.split()[0] == 'ok':
                data = json.loads(' '.join(data.split(' ')[1:]))
    finally:
        sock.close()

    return data


def clean_agents_from_db():
    """
    Clean agents from DB
    """
    command = 'global sql DELETE FROM agent WHERE id != 0'
    try:
        query_wdb(command)
    except Exception:
        raise Exception('Unable to clean agents')


def clean_groups_from_db():
    """
    Clean groups table from global.db
    """
    command = 'global sql DELETE FROM "group"'
    try:
        query_wdb(command)
    except Exception:
        raise Exception('Unable to clean groups table.')


def clean_belongs():
    """
    Clean belong table from global.db
    """
    command = 'global sql DELETE FROM belongs'
    try:
        query_wdb(command)
    except Exception:
        raise Exception('Unable to clean belongs table.')


def insert_agent_in_db(id=1, name='TestAgent', ip='any', registration_time=0, connection_status=0,
                       disconnection_time=0):
    """
    Write agent in global.db
    """
    insert_command = f'global insert-agent {{"id":{id},"name":"{name}","ip":"{ip}","date_add":{registration_time}}}'
    update_command = f'global sql UPDATE agent SET connection_status = "{connection_status}",\
                       disconnection_time = "{disconnection_time}" WHERE id = {id};'
    try:
        query_wdb(insert_command)
        query_wdb(update_command)
    except Exception:
        raise Exception(f"Unable to add agent {id}")


# Insert agents into DB and assign them into a group
def insert_agent_into_group(total_agents):
    for i in range(total_agents):
        id = i + 1
        name = 'Agent-test' + str(id)
        date = time.time()
        command = f'global insert-agent {{"id":{id},"name":"{name}","date_add":{date}}}'
        results = query_wdb(command)
        assert results == 'ok'

        command = f'''global set-agent-groups {{"mode":"append","sync_status":"syncreq",
                   "source":"remote","data":[{{"id":{id},"groups":["Test_group{id}"]}}]}}'''
        results = query_wdb(command)
        assert results == 'ok'


def remove_agent(agent_id):
    """Function that wraps the needed queries to remove an agent.

    Args:
        agent_id(int): Unique identifier of an agent
    """
    data = query_wdb(f"global delete-agent {agent_id}").split()
    assert data[0] == 'ok', f"Unable to remove agent {agent_id} - {data[1]}"


def calculate_global_hash():
    """Function that calculates and retrieves the actual global groups hash.

    Returns:
        str: Actual global groups hash.
    """
    GET_GROUP_HASH = '''global sql SELECT group_hash FROM agent WHERE
                     id > 0 AND group_hash IS NOT NULL ORDER BY id'''

    result = query_wdb(GET_GROUP_HASH)
    group_hashes = [item['group_hash'] for item in result]

    return hashlib.sha1("".join(group_hashes).encode()).hexdigest()
