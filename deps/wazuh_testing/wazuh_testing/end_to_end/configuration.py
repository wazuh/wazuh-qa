# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
"""
Module Name: configuration.py

Description:
    This module provides functions for configuring and managing host configurations using the HostManager class
    and related tools.

Functions:
    - backup_configurations(host_manager: HostManager) -> dict:
        Backup configurations for all hosts in the specified host manager.

    - restore_backup(host_manager: HostManager, backup_configurations: dict) -> None:
        Restore configurations for all hosts in the specified host manager.

    - configure_environment(host_manager: HostManager, configurations: dict) -> None:
        Configure the environment for all hosts in the specified host manager.
        This function uses ThreadPool to parallelize the configuration process.
"""
from multiprocessing.pool import ThreadPool
import xml.dom.minidom

from wazuh_testing.end_to_end import configuration_filepath_os
from wazuh_testing.tools.configuration import set_section_wazuh_conf
from wazuh_testing.tools.system import HostManager



def backup_configurations(host_manager: HostManager) -> dict:
    """
    Backup configurations for all hosts in the specified host manager.

    Args:
        host_manager: An instance of the HostManager class containing information about hosts.

    Returns:
        dict: A dictionary mapping host names to their configurations.
    """
    return {
        str(host): host_manager.get_file_content(str(host), configuration_filepath_os[host_manager.get_host_variables(host)['os_name']])
        for host in host_manager.get_group_hosts('all')
    }


def restore_backup(host_manager: HostManager, backup_configurations: dict) -> None:
    """
    Restore configurations for all hosts in the specified host manager.

    Args:
        host_manager: An instance of the HostManager class containing information about hosts.
        backup_configurations: A dictionary mapping host names to their configurations.
    """
    [host_manager.modify_file_content(str(host), configuration_filepath_os[host_manager.get_host_variables(host)['os_name']], backup_configurations[str(host)])
     for host in host_manager.get_group_hosts('all')]


def configure_host(host: str, host_configuration_role: dict, host_manager: HostManager) -> None:
    """
    Configure a specific host.

    Args:
        host: The name of the host to be configured.
        host_configuration_role: Role of the configured host for the host.
        host_manager: An instance of the HostManager class containing information about hosts.
    """

    host_os = host_manager.get_host_variables(host)['os_name']
    config_file_path = configuration_filepath_os[host_os]

    host_groups = host_manager.get_host_groups(host)
    host_config = host_configuration_role.get('manager' if 'manager' in host_groups else 'agent', None)
    
    if not host_config:
        raise TypeError(f"Host {host} configuration does not include a valid role (manager or agent): {host_configuration_role}")

    current_config = host_manager.get_file_content(str(host), config_file_path)
    new_config = set_section_wazuh_conf(host_config[0].get('sections'), current_config.split("\n"))
    new_config = "\n".join(xml.dom.minidom.parseString(''.join(new_config)).toprettyxml().split("\n")[1:])

    host_manager.modify_file_content(str(host), config_file_path, new_config)


def configure_environment(host_manager: HostManager, configurations: dict) -> None:
    """
    Configure the environment for all hosts in the specified host manager.

    Args:
        host_manager: An instance of the HostManager class containing information about hosts.
        configurations: A dictionary mapping host roles to their configuration details.
    """
    configure_environment_parallel_map = [(host, configurations) for host in host_manager.get_group_hosts('all')]

    with ThreadPool() as pool:
        pool.starmap(configure_host, [(host, config, host_manager) for host, config in configure_environment_parallel_map])

