'''
brief: This module holds common methods and variables for the enrollment tests
copyright:
    Copyright (C) 2015-2021, Wazuh Inc.
    Created by Wazuh, Inc. <info@wazuh.com>.
    This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
'''


import subprocess
import platform

from wazuh_testing.agent import AgentAuthParser
from wazuh_testing.tools import AGENT_AUTH_BINARY_PATH

AGENTD_ENROLLMENT_REQUEST_TIMEOUT = 20
AGENT_AUTH_ENROLLMENT_REQUEST_TIMEOUT = 10
AGENT_AUTH_LAUNCH_TIMEOUT = 2
MANAGER_ADDRESS = '127.0.0.1'


def launch_agent_auth(configuration):
    """Launches agent-auth based on a specific dictionary configuration

    Args:
        configuration (dict): Dictionary with the agent-auth configuration.
    """
    if configuration.get('manager_address'):
        parser = AgentAuthParser(server_address=configuration.get('manager_address'), BINARY_PATH=AGENT_AUTH_BINARY_PATH,
                             sudo=True if platform.system() == 'Linux' else False)
    else:
        parser = AgentAuthParser(server_address=MANAGER_ADDRESS, BINARY_PATH=AGENT_AUTH_BINARY_PATH,
                                 sudo=True if platform.system() == 'Linux' else False)
    if configuration.get('agent_name'):
        parser.add_agent_name(configuration.get("agent_name"))
    if configuration.get('agent_address'):
        parser.add_agent_adress(configuration.get("agent_address"))
    if configuration.get('auto_method') == 'yes':
        parser.add_auto_negotiation()
    if configuration.get('ssl_cipher'):
        parser.add_ciphers(configuration.get('ssl_cipher'))
    if configuration.get('server_ca_path'):
        parser.add_manager_ca(configuration.get('server_ca_path'))
    if configuration.get('agent_key_path'):
        parser.add_agent_certificates(configuration.get('agent_key_path'), configuration.get('agent_certificate_path'))
    if configuration.get('use_source_ip'):
        parser.use_source_ip()
    if configuration.get('password'):
        parser.add_password(configuration.get('password'))
    if configuration.get('groups'):
        parser.add_groups(configuration.get('groups'))

    subprocess.call(parser.get_command(), timeout=AGENT_AUTH_LAUNCH_TIMEOUT)
