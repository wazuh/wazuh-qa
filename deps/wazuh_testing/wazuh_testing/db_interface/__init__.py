import json
import socket
import os
import sys
import sqlite3
from time import sleep

from wazuh_testing import WAZUH_DB_SOCKET_PATH
from wazuh_testing.tools.monitoring import wazuh_pack, wazuh_unpack
from wazuh_testing.tools.services import control_service


def query_wdb(command):
    """Make queries to wazuh-db using the wdb socket.

    Args:
        command (str): wazuh-db command alias. For example `global get-agent-info 000`.

    Returns:
        list: Query response data.
    """
    # If the wdb socket is not yet up, then wait or restart wazuh-db
    if not os.path.exists(WAZUH_DB_SOCKET_PATH):
        max_retries = 6
        for _ in range(2):
            retry = 0
            # Wait if the wdb socket is not still alive (due to wazuh-db restarts). Max 3 seconds
            while not os.path.exists(WAZUH_DB_SOCKET_PATH) and retry < max_retries:
                sleep(0.5)
                retry += 1

            # Restart wazuh-db in case of wdb socket is not yet up.
            if not os.path.exists(WAZUH_DB_SOCKET_PATH):
                control_service('restart', daemon='wazuh-db')

        # Raise custom exception if the socket is not up in the expected time, even restarting wazuh-db
        if not os.path.exists(WAZUH_DB_SOCKET_PATH):
            raise Exception('The wdb socket is not up. wazuh-db was restarted but the socket was not found')

    # Create and open the socket connection with wazuh-db socket
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(WAZUH_DB_SOCKET_PATH)
    data = []

    try:
        # Send the query request
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


def execute_sqlite_query(cursor, query):
    """Execute a sqlite query, retrying in case the database is locked.

    Args:
        cursor (sqlite3.Cursor): Sqlite cursor object.
        query (str): Query to execute.

    Raises:
        sqlite3.OperationalError if database is locked after max retries
    """
    retries = 0
    max_retries = 10
    make_query = True

    # Execute the query, retrying it if necessary up to a maximum number of times.
    while make_query and retries < max_retries:
        try:
            cursor.execute(query)
            make_query = False
        except sqlite3.OperationalError:
            _, exception_message, _ = sys.exc_info()
            if str(exception_message) == 'database is locked':
                sleep(0.5)
                retries += 1

    # If the database is locked after the maximum number of retries, then raise the exception
    if retries == max_retries:
        raise sqlite3.OperationalError('database is locked')


def make_sqlite_query(db_path, query_list):
    """Make a query to the database for each passed query.

    Args:
        db_path (string): Path where is located the DB.
        query_list (list): List with queries to run.
    """
    control_service('stop', daemon='wazuh-db')

    try:
        db_connection = sqlite3.connect(db_path)

        for item in query_list:
            cursor = db_connection.cursor()
            execute_sqlite_query(cursor, item)
            cursor.close()

        db_connection.commit()
    finally:
        db_connection.close()
        control_service('start', daemon='wazuh-db')


def get_sqlite_query_result(db_path, query):
    """Get a query result.

    Args:
        db_path (str): Path where is located the DB.
        query (str): SQL query. e.g(SELECT * ..).

    Returns:
        result (List[list]): Each row is the query result row and each column is the query field value.
    """
    control_service('stop', daemon='wazuh-db')

    try:
        db_connection = sqlite3.connect(db_path)
        try:
            cursor = db_connection.cursor()

            execute_sqlite_query(cursor, query)
            records = cursor.fetchall()
            result = []

            for row in records:
                result.append(', '.join([f"{item}" for item in row]))

            return result
        finally:
            cursor.close()
    finally:
        db_connection.close()
        control_service('start', daemon='wazuh-db')
