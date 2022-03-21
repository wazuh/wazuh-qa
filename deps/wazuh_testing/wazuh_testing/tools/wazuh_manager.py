import os
import subprocess
from wazuh_testing.tools import WAZUH_PATH
from wazuh_testing.wazuh_db import query_wdb


def list_agents_ids():
    wazuhdb_result = query_wdb('global get-all-agents last_id -1')
    list_agents = [agent['id'] for agent in wazuhdb_result if not (0 == agent.get('id'))]

    return list_agents


def remove_agents(agents_id, remove_type='wazuhdb'):
    if remove_type not in ['wazuhdb', 'manage_agents']:
        raise ValueError("Invalid type of agent removal: %s" % remove_type)

    if agents_id:
        for agent_id in agents_id:
            if remove_type == 'manage_agents':
                subprocess.call([f"{WAZUH_PATH}/bin/manage_agents", "-r", f"{agent_id}"], stdout=open(os.devnull, "w"),
                                stderr=subprocess.STDOUT)
            elif remove_type == 'wazuhdb':
                result = query_wdb(f"global delete-agent {str(agent_id)}")


def remove_all_agents(remove_type):
    remove_agents(list_agents_ids(), remove_type)
