"""
Module for change configurations of remote hosts.
----------------------------------------

This module provides functions for configuring and managing remote host
configurations using the HostManager class and related tools.

Functions:
    - backup_configurations: Backup configurations for all hosts in the specified host manager.
    - restore_configuration: Restore configurations for all hosts in the specified host manager.
    - configure_host: Configure a specific host.
    - configure_environment: Configure the environment for all hosts in the specified host manager.


Copyright (C) 2015, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
"""
import ast
import logging
import xml.dom.minidom
from multiprocessing.pool import ThreadPool
from typing import Dict, List

from wazuh_testing.end_to_end import configuration_filepath_os
from wazuh_testing.tools.configuration import (load_configuration_template,
                                               set_section_wazuh_conf)
from wazuh_testing.tools.system import HostManager


def backup_configurations(host_manager: HostManager) -> Dict[str, List]:
    """
    Backup configurations for all hosts in the specified host manager.

    Args:
        host_manager: An instance of the HostManager class containing information about hosts.

    Returns:
        dict: A dictionary mapping host names to their configurations.

    Example of returned dictionary:
        {
            'manager': '<ossec_config>...</ossec_config>',
            'agent1': ...
        }
    """
    logging.info("Backing up configurations")
    backup_configurations = {}

    for host in host_manager.get_group_hosts('all'):
        host_os_name = host_manager.get_host_variables(host)['os_name']
        configuration_filepath = configuration_filepath_os[host_os_name]

        backup_configurations[host] = host_manager.get_file_content(str(host),
                                                                    configuration_filepath)
    logging.info("Configurations backed up")

    return backup_configurations


def restore_configuration(host_manager: HostManager, configuration: Dict[str, List]) -> None:
    """
    Restore configurations for all hosts in the specified host manager.

    Args:
        host_manager: An instance of the HostManager class containing information about hosts.
        configuration: A dictionary mapping host names to their configurations.

    Example of configuration dictionary:
        {
            'manager': '<ossec_config>...</ossec_config>',
            'agent1': ...
        }
    """
    logging.info("Restoring configurations")
    for host in host_manager.get_group_hosts('all'):
        host_os_name = host_manager.get_host_variables(host)['os_name']
        configuration_filepath = configuration_filepath_os[host_os_name]

        host_manager.modify_file_content(host, configuration_filepath, configuration[host])
    logging.info("Configurations restored")


def configure_host(host: str, host_configuration: Dict[str, Dict], host_manager: HostManager) -> None:
    """
    Configure a specific host.

    Args:
        host: The name of the host to be configured.
        host_configuration: Role of the configured host for the host. Check below for example.
        host_manager: An instance of the HostManager class containing information about hosts.

    Note: The host_configuration dictionary must contain a list of sections and elements to be configured. The sections
    not included in the dictionary will not be modified maintaining the current configuration.


    Example of host_configuration dictionary:
        {
           "manager1":[
              {
                 "sections":[
                    {
                       "section":"vulnerability-detection",
                       "elements":[
                          {
                             "enabled":{
                                "value":"yes"
                             }
                          },
                          {
                             "index-status":{
                                "value":"yes"
                             }
                          },
                          {
                             "feed-update-interval":{
                                "value":"2h"
                             }
                          }
                       ]
                    },
             ],
             "metadata":{}
            }
            ],
        }
    """
    logging.info(f"Configuring host {host}")

    host_os = host_manager.get_host_variables(host)['os_name']
    config_file_path = configuration_filepath_os[host_os]

    host_config = host_configuration.get(host)

    if not host_config:
        raise TypeError(f"Host {host} configuration does not include a valid role (manager or agent):"
                        f"{host_configuration}")

    current_config = host_manager.get_file_content(str(host), config_file_path)

    # Extract the sections from the first element of host_config

    sections = host_config[0].get('sections')

    # Combine the current hos configuration and the desired configuration
    new_config_unformatted = set_section_wazuh_conf(sections, current_config.split("\n"))

    # Format new configuration
    new_config_formatted_xml = xml.dom.minidom.parseString(''.join(new_config_unformatted))

    # Get rid of the first no expected XML version line
    new_config_formatted_xml = new_config_formatted_xml.toprettyxml().split("\n")[1:]

    final_configuration = "\n".join(new_config_formatted_xml)

    host_manager.modify_file_content(str(host), config_file_path, final_configuration)

    logging.info(f"Host {host} configured")


def configure_environment(host_manager: HostManager, configurations: Dict[str, List]) -> None:
    """
    Configure the environment for all hosts in the specified host manager.

    Args:
        host_manager: An instance of the HostManager class containing information about hosts.
        configurations: A dictionary mapping host roles to their configuration details.

    Example of host_configurations dictionary:
        {
           "manager1":[
              {
                 "sections":[
                    {
                       "section":"vulnerability-detection",
                       "elements":[
                          {
                             "enabled":{
                                "value":"yes"
                             }
                          },
                          {
                             "index-status":{
                                "value":"yes"
                             }
                          },
                          {
                             "feed-update-interval":{
                                "value":"2h"
                             }
                          }
                       ]
                    },
             ],
             "metadata":{}
            }
            ],
        }
    """
    logging.info("Configuring environment")
    configure_environment_parallel_map = [(host, configurations) for host in host_manager.get_group_hosts('all')]

    with ThreadPool() as pool:
        pool.starmap(configure_host,
                     [(host, config, host_manager) for host, config in configure_environment_parallel_map])

    logging.info("Environment configured")


def save_indexer_credentials_into_keystore(host_manager):
    """
    Save indexer credentials into the keystore.

    Args:
        host_manager: An instance of the HostManager class containing information about hosts.
    """
    keystore_path = '/var/ossec/bin/wazuh-keystore'

    indexer_server = host_manager.get_group_hosts('indexer')[0]
    indexer_server_variables = host_manager.get_host_variables(indexer_server)
    indexer_user = indexer_server_variables['indexer_user']
    indexer_password = indexer_server_variables['indexer_password']

    for manager in host_manager.get_group_hosts('manager'):
        host_manager.run_command(manager, f"{keystore_path} -f indexer -k username -v {indexer_user}")
        host_manager.run_command(manager, f"{keystore_path} -f indexer -k password -v {indexer_password}")


def change_agent_manager_ip(host_manager: HostManager, agent: str, new_manager_ip: str) -> None:
    """Change the manager IP of an agent.

    Args:
        host_manager: An instance of the HostManager class containing information about hosts.
        agent: The name of the agent to be configured.
        new_manager_ip: The new manager IP for the agent.
    """

    server_block = {'server': {'elements': [{'address': {'value': new_manager_ip}}]}}
    configuration = {'sections': [{'section': 'client', 'elements': [server_block]}]}

    new_configuration = {f"{agent}": [configuration]}

    configure_host(agent, new_configuration, host_manager)


def load_vulnerability_detector_configurations(host_manager, configurations_paths, enable=True,
                                               syscollector_interval='1m'):
    """Returns the configurations for Vulnerability testing for the agent and manager roles

    Args:
        host_manager (HostManager): An instance of the HostManager class containing information about hosts.
        configurations_paths (Dict): The paths to the configuration templates for the agent and manager roles.
        enable (bool, optional): Enable or disable the vulnerability detector. Defaults to True.
        syscollector_interval (str, optional): The syscollector interval. Defaults to '1m'.

    Return:
        Dict: Configurations for each role
    """
    configurations = {}
    vd_enable_value = 'yes' if enable else 'no'

    for host in host_manager.get_group_hosts('all'):
        if host in host_manager.get_group_hosts('agent'):
            configurations[host] = load_configuration_template(configurations_paths['agent'],
                                                               [{}], [{}])

            configuration_template_str = str(configurations[host])
            configuration_variables = {
                    'SYSCOLLECTOR_INTERVAL': syscollector_interval
            }

            for key, value in configuration_variables.items():
                configuration_template_str = configuration_template_str.replace(key, value)
                configurations[host] = ast.literal_eval(configuration_template_str)

        elif host in host_manager.get_group_hosts('manager'):
            configuration_template = load_configuration_template(configurations_paths['manager'], [{}], [{}])

            # Replace placeholders by real values
            manager_index = host_manager.get_group_hosts('manager').index(host) + 2
            indexer_server = host_manager.get_group_hosts('indexer')[0]
            indexer_server_variables = host_manager.get_host_variables(indexer_server)

            default_filebeat_key_path = f"/etc/pki/filebeat/node-{manager_index}-key.pem"

            filebeat_key = indexer_server_variables.get('filebeat_key_path',
                                                        default_filebeat_key_path)

            default_filebeat_certificate_path = f"/etc/pki/filebeat/node-{manager_index}.pem"
            filebeat_certificate = indexer_server_variables.get('filebeat_certificate_path',
                                                                default_filebeat_certificate_path)

            default_filebeat_root_ca_path = '/etc/pki/filebeat/root-ca.pem'
            filebeat_root_ca = indexer_server_variables.get('filebeat_root_ca_path',
                                                            default_filebeat_root_ca_path)
            indexer_server = indexer_server_variables.get('indexer_server',
                                                          indexer_server_variables['ip'])

            configuration_variables = {
                'VULNERABILITY_DETECTOR_ENABLE': vd_enable_value,
                'INDEXER_SERVER': indexer_server,
                'FILEBEAT_ROOT_CA': filebeat_root_ca,
                'FILEBEAT_CERTIFICATE': filebeat_certificate,
                'FILEBEAT_KEY': filebeat_key,
            }
            configuration_template_str = str(configuration_template)

            for key, value in configuration_variables.items():
                configuration_template_str = configuration_template_str.replace(key, value)

            configurations[host] = ast.literal_eval(configuration_template_str)

    return configurations
