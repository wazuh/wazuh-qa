import os
import subprocess
import subprocess as sb
from wazuh_testing.tools import WAZUH_PATH
from wazuh_testing.wazuh_db import query_wdb
import sqlite3
import time


def list_agents(fields=['id']):
    global_db_conn = sqlite3.connect(f"{WAZUH_PATH}/queue/db/global.db")
    selected_fields = ''.join(fields)
    global_db_conn.row_factory = lambda cursor, row: row[0]
    cursor = global_db_conn.cursor()
    
    sqlite_response = cursor.execute(f"SELECT id FROM agent").fetchall()
    sqlite_response.remove(0)
    return sqlite_response 


def remove_agents(agents_id):
    print(f"Removing {agents_id}")

    if agents_id:
        for agent_id in agents_id:
           print(f"Removing {str(agent_id)}")
           subprocess.call([f"{WAZUH_PATH}/bin/manage_agents", "-r", f"{agent_id}"], stdout=open(os.devnull, "w"), stderr=subprocess.STDOUT)
           #result =  query_wdb(f"global delete-agent {str(agent_id)}")

def remove_all_agents():
    agent_ids_list = list_agents(['id'])
    remove_agents(agent_ids_list)
