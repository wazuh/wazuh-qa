# Copyright (C) 2015-2022, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import time

from wazuh_testing.tools import WAZUH_PATH
from system import get_id_from_agent


def register_agent(agent, agent_manager, host_manager, id_group=''):
    agent_ip = host_manager.run_command(agent, f'hostname -i')
    agent_name = "Agent-" + str(round(time.time()))

    # Set the IP for the agent to point to host where enrollment will be done
    manager_ip = host_manager.run_command(agent_manager, f'hostname -i')
    host_manager.add_block_to_file(host=agent, path=f"{WAZUH_PATH}/etc/ossec.conf",
                                   after="<address>", before="</address>", replace=manager_ip)

    # Add agent to Master/Worker using agent-auth tool
    if(id_group == ''):
        host_manager.run_command(agent,
                                 f'{WAZUH_PATH}/bin/agent-auth -m {manager_ip} -A {agent_name} -I {agent_ip}')
    else:
        host_manager.run_command(agent,
                                 f'{WAZUH_PATH}/bin/agent-auth -m {manager_ip} -A {agent_name} -I {agent_ip} \
                                    -G {id_group}')

    agent_id = get_id_from_agent(agent, host_manager)

    return [agent_ip, agent_id, agent_name, manager_ip]
