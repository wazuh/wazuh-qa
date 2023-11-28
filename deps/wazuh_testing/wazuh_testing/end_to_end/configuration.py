"""
Configurations handler for remote hosts.
----------------------------------------

This module provides functions for configuring and managing host
configurations using the HostManager class and related tools.

Functions:
    - backup_configurations: Backup configurations for all hosts in the specified host manager.
    - restore_backup: Restore configurations for all hosts in the specified host manager.
    - configure_environment: Configure the environment for all hosts in the specified host manager.


Copyright (C) 2015, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
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
    backup_configurations = {}
    for host in host_manager.get_group_hosts('all'):
        host_os_name = host_manager.get_host_variables(host)['os_name']
        configuration_filepath = configuration_filepath_os[host_os_name]

        backup_configurations[host] = host_manager.get_file_content(str(host),
                                                                    configuration_filepath)

    return backup_configurations


def restore_configuration(host_manager: HostManager, configuration: dict) -> None:
    """
    Restore configurations for all hosts in the specified host manager.

    Args:
        host_manager: An instance of the HostManager class containing information about hosts.
        configuration: A dictionary mapping host names to their configurations.
    """

    for host in host_manager.get_group_hosts('all'):
        host_os_name = host_manager.get_host_variables(host)['os_name']
        configuration_filepath = configuration_filepath_os[host_os_name]

        host_manager.modify_file_content(host, configuration_filepath, configuration[host])


def configure_host(host: str, host_configuration: dict, host_manager: HostManager) -> None:
    """
    Configure a specific host.

    Args:
        host: The name of the host to be configured.
        host_configuration: Role of the configured host for the host.
        host_manager: An instance of the HostManager class containing information about hosts.
    """

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


def configure_environment(host_manager: HostManager, configurations: dict) -> None:
    """
    Configure the environment for all hosts in the specified host manager.

    Args:
        host_manager: An instance of the HostManager class containing information about hosts.
        configurations: A dictionary mapping host roles to their configuration details.
    """
    configure_environment_parallel_map = [(host, configurations) for host in host_manager.get_group_hosts('all')]

    with ThreadPool() as pool:
        pool.starmap(configure_host,
                     [(host, config, host_manager) for host, config in configure_environment_parallel_map])
