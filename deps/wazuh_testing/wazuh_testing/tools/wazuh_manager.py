import os
import subprocess
import subprocess as sb
from wazuh_testing.tools import WAZUH_PATH
from wazuh_testing.wazuh_db import query_wdb
import sqlite3


def list_agents(fields=['id']):
    global_db_conn = sqlite3.connect(f"{WAZUH_PATH}/queue/db/global.db")
    selected_fields = ''.join(fields)
    global_db_conn.row_factory = lambda cursor, row: row[0]
    cursor = global_db_conn.cursor()

    list_agents = []

    try:
        sqlite_response = cursor.execute(f"SELECT id FROM agent").fetchall()
        sqlite_response.remove(0)
        list_agents = sqlite_response 
    except Exception:
        list_agents = []

    return list_agents


def remove_agents(agents_id, wazuh_script=True, wazuh_db_query=False):
    if agents_id:
        for agent_id in agents_id:
            if wazuh_script:
                subprocess.call([f"{WAZUH_PATH}/bin/manage_agents", "-r", f"{agent_id}"], stdout=open(os.devnull, "w"),
                                stderr=subprocess.STDOUT)
            if wazuh_db_query:
                result = query_wdb(f"global delete-agent {str(agent_id)}")

def remove_all_agents():
    agent_ids_list = list_agents(['id'])
    remove_agents(agent_ids_list)
