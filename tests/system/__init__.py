# Copyright (C) 2015-2022, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import json
from multiprocessing.pool import ThreadPool

from wazuh_testing.tools import WAZUH_PATH, LOG_FILE_PATH, CLUSTER_LOGS_PATH, AGENT_GROUPS_BINARY_PATH

# Agent Variables
AGENT_STATUS_ACTIVE = 'active'
AGENT_STATUS_NEVER_CONNECTED = 'never_connected'
AGENT_STATUS_DISCONNECTED = 'disconnected'
AGENT_NO_GROUPS = 'Null'
AGENT_GROUPS_DEFAULT = 'default'


# Error Messages
ERR_MSG_CLIENT_KEYS_IN_MASTER_NOT_FOUND = f'Did not find the expected keys generated in the master node.'
ERR_MSG_FAILED_TO_SET_AGENT_GROUP = 'Failed when trying to set agent group'


# Functions
def get_agent_id(host_manager, node='wazuh-master'):
    # Gets the first agent id in the master's client.keys file
    return host_manager.run_command(node, f'cut -c 1-3 {WAZUH_PATH}/etc/client.keys')


def get_id_from_agent(agent, host_manager):
    # Get the agent id from the agent's client.keys file
    return host_manager.run_command(agent, f'cut -c 1-3 {WAZUH_PATH}/etc/client.keys')


def restart_cluster(hosts_list, host_manager, parallel=False):
    service = 'wazuh'
    state = 'restarted'
    # Restart the cluster's hosts
    if parallel:
        with ThreadPool() as pool:
            pool.starmap(host_manager.control_service,
                         [(host, service, state) for host in hosts_list])
    else:
        for host in hosts_list:
            host_manager.control_service(host=host, service=service, state=state)


def clean_cluster_logs(hosts_list, host_manager):
    # Clean ossec.log and cluster.log
    for host in hosts_list:
        host_manager.clear_file_without_recreate(host=host, file_path=LOG_FILE_PATH)
        if "worker" in host or "master" in host:
            host_manager.clear_file_without_recreate(host=host, file_path=CLUSTER_LOGS_PATH)


def remove_cluster_agents(wazuh_master, agents_list, host_manager, agents_id=None):
    # Removes a list of agents from the cluster using manage_agents
    for agent in agents_list:
        host_manager.control_service(host=agent, service='wazuh', state='stopped')
        host_manager.clear_file(agent, file_path=os.path.join(WAZUH_PATH, 'etc', 'client.keys'))
    if agents_id is None:
        id = get_agent_id(host_manager)
        while id != '':
            host_manager.get_host(wazuh_master).ansible('command', f"{WAZUH_PATH}/bin/manage_agents -r {id}",
                                                        check=False)
            id = get_agent_id(host_manager)
    else:
        for id in agents_id:
            host_manager.get_host(wazuh_master).ansible('command', f"{WAZUH_PATH}/bin/manage_agents -r {id}",
                                                        check=False)


def get_agents_in_cluster(host, host_manager):
    # Get the list of agents in the cluster
    return host_manager.run_command(host, f'{WAZUH_PATH}/bin/cluster_control -a')


def check_keys_file(host, host_manager):
    # Checks that the key file is not empty in a host
    return host_manager.get_file_content(host, os.path.join(WAZUH_PATH, 'etc', 'client.keys'))


def create_new_agent_group(host, group_name, host_manager):
    # Creates an agent group
    host_manager.run_command(host, f"/var/ossec/bin/agent_groups -q -a -g {group_name}")


def assign_agent_to_new_group(host, id_group, id_agent, host_manager):
    # Add agent to a group
    host_manager.run_command(host, f"/var/ossec/bin/agent_groups -q -a -i {id_agent} -g {id_group}")


def delete_agent_group(host, id_group, host_manager, method='tool'):
    """Function to delete a group.
    Args:
        host (str): Host name where the query will be executed.
        id_group (str): Name of the group from which the id will be obtained.
        host_manager (obj): Instance of HostManager.
        method (str): Method to be used to delete the group. Default:  tool.
    """
    if method == 'tool':
        host_manager.run_command(host, f"{AGENT_GROUPS_BINARY_PATH} -q -r -g {id_group}")
    elif method == 'api':
        master_token = host_manager.get_api_token(host)
        host_manager.make_api_call(host=host, method='DELETE', token=master_token,
                                   endpoint=f"/groups?groups_list={id_group}")
    elif method == 'folder':
        host_manager.run_command(host, f"rm -rf /var/ossec/etc/shared/{id_group}")
    else:
        raise ValueError(f"{method} is not a valid method, it should be tool, api or folder")


def check_agent_groups(agent_id, group_to_check, hosts_list, host_manager):
    # Check the expected group is in the group data for the agent
    for host in hosts_list:
        group_data = host_manager.run_command(host, f'{WAZUH_PATH}/bin/agent_groups -s -i {agent_id}')
        assert group_to_check in group_data, f"Did not recieve expected agent group: {group_to_check} in data \
                                               {str(group_data)} in host {host}"


# Check the expected group is in the group data for the agent in db
def check_agent_groups_db(query, group_to_check, host, host_manager):
    group_data = host_manager.run_command(host, f"python3 {WAZUH_PATH}/bin/wdb-query.py global \
                                          '{query}'")
    assert group_to_check in group_data, f"Did not recieve expected agent group: {group_to_check} in data \
                                         {str(group_data)}"


def check_agent_status(agent_id, agent_name, agent_ip, status, host_manager, hosts_list):
    # Check the agent has the expected status (never_connected, pending, active, disconnected)
    expected_status = f"{agent_id}  {agent_name}  {agent_ip}  {status}"
    for host in hosts_list:
        expected_status = f"{agent_id}  {agent_name}  {agent_ip}  {status}"
        data = get_agents_in_cluster(host, host_manager)
        assert expected_status in data, f" Did not recieve expected agent status {expected_status} in data {str(data)}"


def check_agents_status_in_node(agent_expected_status_list, host, host_manager):
    # Checks the expected status o of different agent in a host.
    # List format: [f"{agent_id}  {agent_name}  {agent_ip}  {status}",...]
    data = get_agents_in_cluster(host, host_manager)
    for status in agent_expected_status_list:
        assert status in data, f" Did not recieve expected agent status: {status} in data {str(data)}"


def change_agent_group_with_wdb(agent_id, new_group, host, host_manager):
    # Uses wdb commands to change the group of an agent

    query = f'{{"mode":"append","sync_status":"syncreq","source":"remote","data":[{{"id":{agent_id}, \
             "groups":["{new_group}"]}}]}}'
    group_data = host_manager.run_command(host, f"python3 {WAZUH_PATH}/bin/wdb-query.py global \
                                          'set-agent-groups {query}'")
    return group_data


def execute_wdb_query(query, host, host_manager):
    """Function to execute wdb query.
    Args:
        query (str): Query to execute
        host (str): Host name where the query will be executed.
        host_manager (obj): Instance of HostManager.
    Returns:
        response (str): Obtained response.
    """
    response = host_manager.run_command(host, f"python3 {WAZUH_PATH}/bin/wdb-query.py {query}")

    return response


def get_group_id(group_name, host, host_manager):
    """Function to obtain the group ID.
    Args:
        group_name (str): Name of the group from which the id will be obtained.
        host (str): Host name where the query will be executed.
        host_manager (obj): Instance of HostManager.
    Returns:
        group_id (int): Obtained group ID.
    """
    group_table_command = 'sql select * from `group`;'
    query = f"global '{group_table_command}'"
    group_table = execute_wdb_query(query, host, host_manager)
    for group_data in json.loads(group_table):
        if group_data['name'] == group_name:
            group_id = group_data['id']

    return group_id


def unassign_agent_from_group(host, id_group, agent_id, host_manager):
    # Unassign agent from group
    host_manager.run_command(host, f"/var/ossec/bin/agent_groups -q -r -g {id_group} -i {agent_id}")
