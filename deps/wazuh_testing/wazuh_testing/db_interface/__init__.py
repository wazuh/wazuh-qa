import json
import socket
import os
import sqlite3
from time import sleep

from wazuh_testing.tools.monitoring import wazuh_pack, wazuh_unpack
from wazuh_testing.tools.services import control_service
import wazuh_testing


QUEUE_DB_PATH = os.path.join(wazuh_testing.WAZUH_PATH, 'queue', 'db')
WAZUH_DB_SOCKET_PATH = os.path.join(QUEUE_DB_PATH, 'wdb')

CVE_DB_PATH = os.path.join(wazuh_testing.WAZUH_PATH, 'queue', 'vulnerabilities', 'cve.db')


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
                print("Retrying ...")
                sleep(0.5)
                retry += 1

            # Restart wazuh-db in case of wdb socket is not yet up.
            if not os.path.exists(WAZUH_DB_SOCKET_PATH):
                print("Restarting wazuh-db ...")
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


def load_sqlite_db(db_path):
    """Load a sqlite database.

    Args:
        db_path (str): Path where is located the DB.

    Returns:
        Connection: connection to the database.
        Cursor: cursor to the database.
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    return conn, cursor


def make_sqlite_query(db_path, query_list):
    """Make a query to the database for each passed query.

    Args:
        db_path (string): Path where is located the DB.
        query_list (list): List with queries to run.
    """
    connect = sqlite3.connect(db_path)

    try:
        with connect:
            for item in query_list:
                connect.execute(item)
    finally:
        connect.close()


def get_sqlite_query_result(db_path, query):
    """Get a query result.

    Args:
        db_path (str): Path where is located the DB.
        query (str): SQL query. e.g(SELECT * ..).

    Returns:
        result (List[list]): Each row is the query result row and each column is the query field value.
    """
    try:
        db, cursor = load_sqlite_db(db_path)
        cursor.execute(query)
        records = cursor.fetchall()
        result = []

        for row in records:
            result.append(', '.join([f"{item}" for item in row]))

        return result

    finally:
        cursor.close()
        db.close()
