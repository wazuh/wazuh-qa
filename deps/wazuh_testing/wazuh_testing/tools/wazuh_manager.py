import os
import subprocess
import requests
from typing import List

from wazuh_testing.tools import WAZUH_PATH
from wazuh_testing.tools.local_actions import run_local_command_returning_output
from wazuh_testing.tools.utils import retry
from wazuh_testing.wazuh_db import query_wdb
from wazuh_testing.api import get_api_details_dict


def list_agents_ids():
    wazuhdb_result = query_wdb('global get-all-agents last_id -1')
    list_agents = [agent['id']
                   for agent in wazuhdb_result if not (0 == agent.get('id'))]

    return list_agents


def remove_agents(agents_id, remove_type='wazuhdb'):
    if remove_type not in ['wazuhdb', 'manage_agents', 'api']:
        raise ValueError("Invalid type of agent removal: %s" % remove_type)

    if agents_id:
        for agent_id in agents_id:
            if remove_type == 'manage_agents':
                subprocess.call([f"{WAZUH_PATH}/bin/manage_agents", "-r",
                                 f"{agent_id}"], stdout=open(os.devnull, "w"),
                                stderr=subprocess.STDOUT)
            elif remove_type == 'wazuhdb':
                result = query_wdb(f"global delete-agent {str(agent_id)}")
        if remove_type == 'api':
            api_details = get_api_details_dict()
            payload = {
                'agents_list': agents_id,
                'status': 'all',
                'older_than': '0s'
            }
            url = f"{api_details['base_url']}/agents"
            response = requests.delete(
                url, headers=api_details['auth_headers'], params=payload, verify=False)
            response_data = response.json()
            if response.status_code != 200:
                raise RuntimeError(f"Error deleting an agent: {response_data}")


def remove_all_agents(remove_type):
    remove_agents(list_agents_ids(), remove_type)


@retry(AttributeError, attempts=10, delay=5, delay_multiplier=1)
def wait_agents_active_by_name(agents_names: List[str]):
    """Wait until all agents received in the agents_name list are active.

    Args:
        agents_names (list[str]): The list with agents names to check.
    Raises:
        AttributeError: If any agent is not active. Combined with the retry
            decorator makes a wait loop until all the agents are active.
    """
    for name in agents_names:
        name = name.replace("\r", "").replace("\n", "")
        command = f'{WAZUH_PATH}/bin/agent_control -l | grep "{name}"'
        if not 'Active' in run_local_command_returning_output(command):
            raise AttributeError(f"Agent {name} is not active yet.")
    return True
