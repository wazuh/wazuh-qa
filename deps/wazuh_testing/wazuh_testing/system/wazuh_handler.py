# Copyright (C) 2015-2022, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import re

from wazuh_testing.system.host_manager import HostManager

DEFAULT_INSTALL_PATH = {
    'linux': '/var/ossec',
    'windows': 'C:\\Program Files\\ossec-agent',
    'darwin': '/Library/Ossec'
}


def get_configuration_directory_path(custom_installation_path=None, os_host='linux'):
    installation_path = custom_installation_path if custom_installation_path else DEFAULT_INSTALL_PATH[os_host]
    return installation_path if os_host == 'windows' else os.path.join(installation_path, 'etc')


def get_custom_decoders_directory_path(custom_installation_path=None):
    installation_path = custom_installation_path if custom_installation_path else DEFAULT_INSTALL_PATH['linux']
    return os.path.join(installation_path, 'etc', 'decoders')


def get_custom_rules_directory_path(custom_installation_path=None):
    installation_path = custom_installation_path if custom_installation_path else DEFAULT_INSTALL_PATH['linux']
    return os.path.join(installation_path, 'etc', 'rules')


def get_api_directory(custom_installation_path=None):
    installation_path = custom_installation_path if custom_installation_path else DEFAULT_INSTALL_PATH['linux']
    return os.path.join(installation_path, 'api')


def get_api_configuration_directory(custom_installation_path=None):
    installation_path = custom_installation_path if custom_installation_path else DEFAULT_INSTALL_PATH['linux']
    return os.path.join(get_api_directory(custom_installation_path), 'configuration')


def get_alert_directory_path(custom_installation_path=None):
    installation_path = custom_installation_path if custom_installation_path else DEFAULT_INSTALL_PATH['linux']
    return os.path.join(installation_path, 'logs', 'alerts')


def get_archives_directory_path(custom_installation_path=None):
    installation_path = custom_installation_path if custom_installation_path else DEFAULT_INSTALL_PATH['linux']
    return os.path.join(installation_path, 'logs', 'archives')


def get_logs_directory_path(custom_installation_path=None, os_host='linux'):
    installation_path = custom_installation_path if custom_installation_path else DEFAULT_INSTALL_PATH[os_host]
    return installation_path if os_host == 'windows' else os.path.join(installation_path, 'logs')


def get_shared_directory_path(custom_installation_path=None, os_host='linux'):
    installation_path = custom_installation_path if custom_installation_path else DEFAULT_INSTALL_PATH[os_host]
    return os.path.join(get_configuration_directory_path(installation_path, os_host), 'shared')


def get_group_configuration_directory(custom_installation_path=None, os_host='linux', component='manager',
                                      group_name='default'):
    installation_path = custom_installation_path if custom_installation_path else DEFAULT_INSTALL_PATH[os_host]
    group_configuration_path = None
    if component == 'manager':
        group_configuration_path = os.path.join(get_shared_directory_path(custom_installation_path, os_host),
                                                group_name)
    else:
        group_configuration_path = os.path.join(get_shared_directory_path(custom_installation_path, os_host))

    return group_configuration_path


def get_ruleset_directory(custom_installation_path=None, os='linux'):
    installation_path = custom_installation_path if custom_installation_path else DEFAULT_INSTALL_PATH[os]
    return os.path.join(installation_path, 'ruleset')


def get_wazuh_file_path(custom_installation_path=None, os_host='linux', file_name=None, component=None, **extra_params):
    """Get the Wazuh file paths

    Args:
        custom_installation_path (str): Custom installation path.
        os (str): Operating system.
    Returns:
        str: Wazuh installation path.
    """
    installation_path = custom_installation_path if custom_installation_path else DEFAULT_INSTALL_PATH[os_host]
    group = extra_params.get('group', 'default')

    wazuh_directory_files = {
        'general_configuration': {
            'files': ['ossec.conf', 'client.keys', 'local_internal_options.conf', 'internal_options.conf'],
            'path_calculator': lambda filename: os.path.join(get_configuration_directory_path(installation_path,
                                                                                              os_host),
                                                             filename)
        },
        'api_configuration': {
            'files': ['api.yaml'],
            'path_calculator': lambda filename: os.path.join(get_api_configuration_directory(installation_path),
                                                             filename)
        },
        'general_logs': {
            'files': ['ossec.log', 'active-responses.log', 'api.log', 'cluster.log', 'integrations.log'],
            'path_calculator': lambda filename: os.path.join(get_logs_directory_path(installation_path, os_host),
                                                             filename)
        },
        'alert_directory': {
            'files': ['alerts.json', 'alerts.log'],
            'path_calculator': lambda filename: os.path.join(get_alert_directory_path(installation_path), filename)
        },
        'archives_directory': {
            'files': ['archives.json', 'archives.log'],
            'path_calculator': lambda filename: os.path.join(get_archives_directory_path(installation_path), filename)
        },
        'custom_decoder_directory': {
            'files': ['local_decoders.xml'],
            'path_calculator': lambda filename: os.path.join(get_custom_decoders_directory_path(installation_path),
                                                             filename)
        },
        'custom_rule_directory': {
            'files': ['local_rules.xml'],
            'path_calculation': lambda filename: os.path.join(get_custom_rules_directory_path(installation_path),
                                                              filename)
        },
        'group_configuration': {
            'files': ['agent.conf'],
            'path_calculator': lambda filename: os.path.join(get_group_configuration_directory(installation_path,
                                                                                               os_host,
                                                                                               group_name=group,
                                                                                               component=component),
                                                             filename)
        }
    }
    for files in wazuh_directory_files.values():
        if file_name in files['files']:
            return files['path_calculation'](file_name)


class WazuhEnvironmentHandler(HostManager):
    def __init__(self, inventory_path):
        super().__init__(inventory_path)

    def get_file_fullpath(self, host, filename, group=None):
        """Get the path of common configuration and log file in the specified host.
        Args:
            host (str): Hostname
            filename (str): File name
            group (str): Group name. Default `None`
        Returns:
            str: Path of the file
        """
        wazuh_installation_path = self.get_host_variables(host).get('wazuh_installation_path', None)

        return get_wazuh_file_path(custom_installation_path=wazuh_installation_path,
                                   os_host=self.get_ansible_host_os(host),
                                   file_name=filename, group=group, component=self.get_ansible_host_component(host))

    def get_configuration_directory_path(self, host):
        """Get the path of configuration directory in the specified host.
        Args:
            host (str): Hostname
        Returns:
            str: Path of the configuration directory
        """
        custom_installation_path = self.get_host_variables(host).get('wazuh_installation_path', None)
        host_os = self.get_ansible_host_os(host)

        return get_configuration_directory_path(custom_installation_path=custom_installation_path,
                                                os_host=host_os)

    def get_custom_decoders_directory_path(self, host):
        """Get the path of custom decoders directory in the specified host.
        Args:
            host (str): Hostname
        Returns:
            str: Path of the custom decoders directory
        """
        custom_installation_path = self.get_host_variables(host).get('wazuh_installation_path', None)
        host_os = self.get_ansible_host_os(host)
        host_component = self.get_ansible_host_component(host)

        if host_component == 'manager':
            custom_decoders_directory_path = get_custom_decoders_directory_path(custom_installation_path,
                                                                                os_host=host_os)
        else:
            custom_decoders_directory_path = None

        return custom_decoders_directory_path

    def get_custom_rules_directory_path(self, host):
        """Get the path of custom rules directory in the specified host.
        Args:
            host (str): Hostname
        Returns:
            str: Path of the custom rules directory
        """
        custom_installation_path = self.get_host_variables(host).get('wazuh_installation_path', None)
        host_os = self.get_ansible_host_os(host)
        host_component = self.get_ansible_host_component(host)

        if host_component == 'manager':
            custom_rules_directory_path = get_custom_rules_directory_path(custom_installation_path,
                                                                          os_host=host_os)
        else:
            custom_rules_directory_path = None

        return custom_rules_directory_path

    def get_api_directory(self, host):
        """Get the path of API directory in the specified host.
        Args:
            host (str): Hostname
        Returns:
            str: Path of the API directory
        """
        custom_installation_path = self.get_host_variables(host).get('wazuh_installation_path', None)
        host_os = self.get_ansible_host_os(host)
        host_component = self.get_ansible_host_component(host)

        if host_component == 'manager':
            api_directory = get_api_directory(custom_installation_path, host_os)
        else:
            api_directory = None

        return api_directory

    def get_api_configuration_directory(self, host):
        """Get the path of API configuration directory in the specified host.
        Args:
            host (str): Hostname
        Returns:
            str: Path of the API configuration directory
        """
        custom_installation_path = self.get_host_variables(host).get('wazuh_installation_path', None)
        host_os = self.get_ansible_host_os(host)
        host_component = self.get_ansible_host_component(host)

        if host_component == 'manager':
            api_configuration_directory = get_api_configuration_directory(custom_installation_path, host_os)
        else:
            api_configuration_directory = None

        return api_configuration_directory

    def get_alerts_directory_path(self, host):
        """Get the path of alert directory in the specified host.
        Args:
            host (str): Hostname
        Returns:
            str: Path of the alert directory
        """
        custom_installation_path = self.get_host_variables(host).get('wazuh_installation_path', None)
        host_os = self.get_ansible_host_os(host)
        host_component = self.get_ansible_host_component(host)

        if host_component == 'manager':
            alert_directory_path = get_alert_directory_path(custom_installation_path, host_os)
        else:
            alert_directory_path = None

        return alert_directory_path

    def get_archives_directory_path(self, host):
        """Get the path of archives directory in the specified host.
        Args:
            host (str): Hostname
        Returns:
            str: Path of the archives directory
        """
        custom_installation_path = self.get_host_variables(host).get('wazuh_installation_path', None)
        host_os = self.get_ansible_host_os(host)
        host_component = self.get_ansible_host_component(host)

        if host_component == 'manager':
            archives_directory_path = get_archives_directory_path(custom_installation_path, host_os)
        else:
            archives_directory_path = None

        return archives_directory_path

    def get_logs_directory_path(self, host):
        """Get the path of logs directory in the specified host.
        Args:
            host (str): Hostname
        Returns:
            str: Path of the logs directory
        """
        custom_installation_path = self.get_host_variables(host).get('wazuh_installation_path', None)
        host_os = self.get_ansible_host_os(host)

        logs_directory_path = get_logs_directory_path(custom_installation_path, host_os)

        return logs_directory_path

    def get_shared_directory_path(self, host):
        """Get the path of shared directory in the specified host.
        Args:
            host (str): Hostname
        Returns:
            str: Path of the shared directory
        """
        custom_installation_path = self.get_host_variables(host).get('wazuh_installation_path', None)
        host_os = self.get_ansible_host_os(host)

        shared_directory_path = get_shared_directory_path(custom_installation_path, host_os)

        return shared_directory_path

    def get_group_configuration_directory_path(self, host, group='default'):
        """Get the path of group configuration directory in the specified host.
        Args:
            host (str): Hostname
        Returns:
            str: Path of the group configuration directory
        """
        custom_installation_path = self.get_host_variables(host).get('wazuh_installation_path', None)
        host_os = self.get_ansible_host_os(host)
        host_component = self.get_ansible_host_component(host)

        group_configuration_directory_path = get_group_configuration_directory(custom_installation_path, host_os,
                                                                               group, host_component)

        return group_configuration_directory_path

    def get_ruleset_directory_path(self, host):
        """Get the path of ruleset directory in the specified host.
        Args:
            host (str): Hostname
        Returns:
            str: Path of the ruleset directory
        """
        custom_installation_path = self.get_host_variables(host).get('wazuh_installation_path', None)
        host_os = self.get_ansible_host_os(host)

        ruleset_directory_path = get_ruleset_directory(custom_installation_path, host_os)

        return ruleset_directory_path

    def configure_host(self, host, configuration_host):
        """Configure ossec.conf, agent.conf, api.conf and local_internal_options of specified host of the environment
        Configuration should fit the format expected for each configuration file:
        - ossec and agent.conf configuration should be provided as a list of configuration sections section.
        - local_internal_options configuration should be provided as a map
        - api.yaml should be provided as a map

        Example:
            local_internal_options:
                remoted.debug: 2
                wazuh_modulesd.debug: 2
            ossec.conf:
                - 'section': 'client',
                  'elements':
                  - 'server':
                        'elements':
                            - 'address':
                                'value': 121.1.3.1
            agent.conf:
                - 'group': 'default',
                - configuration:
                    - 'section': 'client',
                      'elements':
                        - 'server':
                            'elements':
                                - 'address':
                                    'value': 121.1.3.1
        Args:
            host (str): Hostname
            configuration_host (Map): Map with new hosts configuration
        """
        pass

    def configure_environment(self, configuration_hosts, parallel=True):
        """Configure multiple hosts at the same time.
        Example:
        wazuh-agent1:
            local_internal_options:
                remoted.debug: 2
                wazuh_modulesd.debug: 2
            ossec.conf:
                - 'section': 'client',
                  'elements':
                  - 'server':
                        'elements':
                            - 'address':
                                'value': 121.1.3.1
            api.yml:
                ....
        wazuh-agent2:
            ossec.conf:
                ...
        Args:
            configuration_host (Map): Map with new hosts configuration
            parallel(Boolean): Enable parallel tasks
        """
        pass

    def change_agents_configure_manager(self, agent_list, manager, use_manager_name=True):
        """Change configured manager of specified agent

        Args:
            agent (str): Agent name.
            manager (str): Manager name in the environment/Manager or IP.
            use_manager_name (Boolean): Replace manager name with manager IP. Default True
        """
        pass

    def backup_host_configuration(self, configuration_list):
        """Backup specified files in

        Args:
            configuration_list (dict): Host configuration files to backup
        Returns:
            dict: Host backup filepaths
        """

    def backup_environment_configuration(self, configuration_list, parallel=True):
        """Backup specified files in all hosts

        Args:
            configuration_list (dict): Host configuration files to backup
        Returns:
            dict: Host backup filepaths
        """
        pass

    def restore_host_backup_configuration(self, backup_configuration):
        """Restore backup configuration

        Args:
            backup_configuration (dict): Backup configuration filepaths
        """
        pass

    def restore_environment_backup_configuration(self, backup_configuration, parallel=True):
        """Restore environment backup configuration

        Args:
            backup_configuration (dict): Backup configuration filepaths
        """
        pass

    def log_search(self, host, pattern, timeout, file, escape=False, output_file='log_search_output.json'):
        """Search log in specified host file

        Args:
            host (str): Hostname
            pattern (str): Pattern to search
            timeout (int): Timeout
            file (str): Filepath
            escape (bool, optional): Escape special characters. Defaults to False.
            output_file (str, optional): Match results file. Defaults to 'find.json'.

        Returns:
            dict: Match results
        """
        pass

    def log_multisearch(self, multipattern_search, file, escape=False):
        """Multihost log pattern

        Args:
            multipattern_search (dict): Multihost and multipattern  dictionary
            file (str, optional): Filepath.
            escape (bool, optional): Escape special characters. Defaults to False.
        Returns:
            srt: Search results
        """
        pass

    def get_ansible_host_os(self, host):
        """Get host os

        Args:
            host (str): Hostname

        Returns:
            str: Host os
        """
        return self.get_host_variables(host)['os_name']

    def get_ansible_host_component(self, host):
        """Get host os

        Args:
            host (str): Hostname

        Returns:
            str: Host os
        """
        agent_list = self.get_agents()
        manager_list = self.get_managers()
        return 'agent' if host in agent_list else 'manager' if host in manager_list else None

    def restart_agent(self, host):
        """Restart agent

        Args:
            host (str): Hostname
            systemd (bool, optional): Restart using systemd. Defaults to False.
        """
        pass

    def get_agents_info(self):
        """Get registered agents information.

        Returns:
            dict: Agent information
        """
        pass

    def get_agents_id(self, agents_list=None):
        """Get agents id

        Returns:
            List: Agents id list
        """
        pass

    def restart_agents(self, agent_list=None, parallel=True):
        """Restart list of agents

        Args:
            agent_list (list, optional): Agent list. Defaults to None.
        """
        pass

    def restart_manager(self, host):
        """Restart manager

        Args:
            host (str): Hostname
            systemd (bool, optional): Use systemd. Defaults to False.
        """
        pass

    def restart_managers(self, manager_list, parallel=True):
        """Restart managers

        Args:
            manager_list (list): Managers list
        """
        pass

    def stop_agent(self, host):
        """Stop agent

        Args:
            host (str): Hostname
            systemd (bool, optional): Use systemd. Defaults to False.
        """
        pass

    def stop_agents(self, agent_list=None, parallel=True):
        """Stop agents

        Args:
            agent_list(list, optional): Agents list. Defaults to None
        """
        pass

    def get_master_node(self):
        """Get master manager hostname

        Returns:
            str: Manager master node
        """
        pass

    def get_api_details(self):
        """Get api details

        Returns:
            dict: Api details
        """
        pass

    def clean_client_keys(self, hosts=None):
        """Clean client keys

        Args:
            hosts (str, optional): Hostname. Defaults to None.
        """
        pass

    def clean_agents(self, agents=None):
        """Stop agents, remove them from manager and clean their client keys

        Args:
            agents (_type_, agents_list): Agents list. Defaults to None.
        """
        pass

    def remove_agents_from_manager(self, agents=None, status='all', older_than='0s'):
        """Remove agents from manager

        Args:
            agents (list, optional): Agents list. Defaults to None.
            status (str, optional): Agents status. Defaults to 'all'.
            older_than (str, optional): Older than parameter. Defaults to '0s'.

        Returns:
            dict: API response
        """
        pass

    def stop_manager(self, manager):
        """Stop manager

        Args:
            host (Hostname): Hostname
            systemd (bool, optional): Use systemd. Defaults to False.
        """
        pass

    def start_agent(self, gent):
        """Start agent

        Args:
            host (str): Hostname
            systemd (bool, optional): Use systemd. Defaults to False.
        """
        pass

    def start_agents(self, agent_list, parallel=True):
        """Start agents

        Args:
            agent_list (list): Agents list
        """
        pass

    def start_manager(self, manager):
        """Start manager

        Args:
            host (str): Hostname
        """
        pass

    def start_managers(self, manager_list, parallel=True):
        """Start managers

        Args:
            manager_list (list): Managers list
        """
        pass

    def restart_environment(self, parallel=True):
        """Restart all agents and manager in the environment

        Args:
            parallel (bool, optional): Parallel execution. Defaults to True.
        """
        pass

    def get_host_ansible_ip(self, host):
        """Get host used ip by ansible.

        Args:
            host (str): Hostname

        Returns:
            str: Host used IP
        """
        ansible_ip = self.get_host_variables(host).get('ansible_host', None)
        return ansible_ip

    def is_windows(self, host):
        """Check if host is windows

        Args:
            host (str): Hostname

        Returns:
            boolean: Host is a windows host
        """
        return self.get_host_variables(host)['os_name'] == 'windows'

    def is_linux(self, host):
        """Check if host is Linux

        Args:
            host (str): Hostname

        Returns:
            boolean: Host is a linux host
        """
        return self.get_host_variables(host)['os_name'] == 'linux'

    def is_macos(self, host):
        """Check if host is macos

        Args:
            host (str): Hostname

        Returns:
            boolean: Host is a macos host
        """
        return self.get_host_variables(host)['os_name'] == 'darwin'

    def get_managers(self):
        """Get environment managers names

        Returns:
            List: Managers names list
        """
        return self.get_group_hosts('manager')

    def get_agents(self):
        """Get environment agents names

        Returns:
            List: Agent names list
        """
        return self.get_group_hosts('agent')
