# Copyright (C) 2015-2022, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

from wazuh_testing.tools import WAZUH_PATH, WAZUH_LOGS_PATH


def restart_cluster(hosts_list, host_manager):
    # Restart the cluster's hosts
    for host in hosts_list:
        if "agent" in host:
            host_manager.get_host(host).ansible('command', f'service wazuh-agent restart', check=False)
        host_manager.control_service(host=host, service='wazuh', state="restarted")


def clean_cluster_logs(hosts_list, host_manager):
    # Clean ossec.log and cluster.log
    for host in hosts_list:
        host_manager.clear_file(host=host, file_path=os.path.join(WAZUH_LOGS_PATH, 'ossec.log'))
        if "worker" in host or "master" in host:
            host_manager.clear_file(host=host, file_path=os.path.join(WAZUH_LOGS_PATH, 'cluster.log'))


def get_agent_id(host_manager):
    return host_manager.run_command('wazuh-master', f'cut -c 1-3 {WAZUH_PATH}/etc/client.keys')


def get_agents_in_cluster(host, host_manager):
    return host_manager.run_command(host, f'{WAZUH_PATH}/bin/cluster_control -a')


def check_keys_file(host, host_manager):
    return host_manager.get_file_content(host, os.path.join(WAZUH_PATH, 'etc', 'client.keys'))


# Create new group and assing agent
def assign_agent_to_new_group(host, id_group, id_agent, host_manager):
    # Create group
    host_manager.run_command(host, f"/var/ossec/bin/agent_groups -q -a -g {id_group}")

    # Add agent to a group
    host_manager.run_command(host, f"/var/ossec/bin/agent_groups -q -a -i {id_agent} -g {id_group}")


def delete_group_of_agents(host, id_group, host_manager):
    # Delete group
    host_manager.run_command(host, f"/var/ossec/bin/agent_groups -q -r -g {id_group}")
