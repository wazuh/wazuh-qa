# Copyright (C) 2015-2022, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import re

from wazuh_testing.system.host_manager import HostManager

class WazuhAPI(HostManager):

    def __init__(self, inventory_path):
        super().__init__(inventory_path)

    def get_file_path(self, host, filename, group=None):
        """Get the path of a configuration or log file in specified host.
        Args:
            host (str): Hostname
            filename (str): File name
            group (str): Group name
        Returns:
            str: Path of the file
        """
        custom_path = self.get_host_variables(host).get('wazuh_custom_path', None)
        os_name = self.get_host_variables(host).get('os_name')
        is_windows = os_name == 'windows'
        is_macos = os_name == 'darwin'

        filepath = None

        if not custom_path:
            if is_macos:
                install_path = '/Library/Ossec'
            elif is_windows:
                install_path = 'C:\\Program Files\\ossec'
            else:
                install_path = '/var/ossec'
        else:
            install_path = custom_path

        if filename == 'ossec.conf' or filename == 'local_internal_options.conf':
            filepath = os.path.join(install_path, 'etc', filename) if not is_windows else \
                                    os.path.join(install_path, filename)

        elif filename == 'ossec.log':
            filepath = os.path.join(install_path, 'logs', filename) if not is_windows else os.path.join(install_path, filename)

        elif filename == 'alert.json':
            filepath = os.path.join(install_path, 'logs', 'alerts', filename)

        elif filename == 'api.yaml':
            filepath = os.path.join(install_path, 'api', 'configuration', filename)

        elif filename == 'api.log':
            filepath = os.path.join(install_path, 'logs', filename)

        elif filename == 'cluster.log':
            filepath = os.path.join(install_path, 'logs', filename)

        elif filename == 'client.keys':
            filepath = os.path.join(install_path, 'etc', filename) if not is_windows else os.path.join(install_path, filename)

        elif filename == 'agent.conf':
            if not group:
                group = 'default'

            if host in self.get_group_hosts('agents'):
                filepath = os.path.join(install_path, 'etc', 'shared', filename)
            else:
                filepath = os.path.join(install_path, 'etc', 'shared', group, filename)

        elif filename == 'internal_configuration.conf':
            filepath = os.path.join(install_path, 'etc', 'internal_options.conf') if not windows else \
                                    os.path.join(install_path, 'internal_options.conf')

        return filepath


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

    def change_agents_configure_manager(self, agent_list , manager, use_manager_name=True):
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
        return self.get_group_hosts('managers')

    def get_agents(self):
        """Get environment agents names

        Returns:
            List: Agent names list
        """
        return self.get_group_hosts('agents')

    def get_hosts(self, regex, group='all'):
        """Get hosts of the environment that match a regex

        Args:
            regex (str): Regex to match
            group (str, optional): Group of hosts. Defaults to 'all'.

        Returns:
            List: List of hosts that match regex and group
        """
        environment_information = self.get_host_variables(group)
        regex = re.compile(regex)
        return list(filter(regex.match, environment_information['groups'][group]))

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

    def get_agents_id(self):
        """Get agents id

        Returns:
            List: Agents id list
        """
        pass

    def restart_agents(self, agent_list=None):
        """Restart list of agents

        Args:
            agent_list (list, optional): Agent list. Defaults to None.
        """
        pass

    def restart_manager(self, host, systemd=False):
        """Restart manager

        Args:
            host (str): Hostname
            systemd (bool, optional): Use systemd. Defaults to False.
        """
        pass

    def restart_managers(self, manager_list):
        """Restart managers

        Args:
            manager_list (list): Managers list
        """
        pass

    def stop_agent(self, host, systemd=False):
        """Stop agent

        Args:
            host (str): Hostname
            systemd (bool, optional): Use systemd. Defaults to False.
        """
        pass

    def stop_agents(self, agent_list=None):
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

    def make_api_call(self, port=55000, method='GET', endpoint='/', request_body=None, headers=None, params=None):
        """Make call to master API

        Args:
            port (int, optional): Port. Defaults to 55000.
            method (str, optional): Method. Defaults to 'GET'.
            endpoint (str, optional): Endpoint. Defaults to '/'.
            request_body (_type_, optional): Request body. Defaults to None.
            headers (_type_, optional): Headers. Defaults to None.
            params (_type_, optional): Params. Defaults to None.

        Returns:
            dict: API response
        """

    def get_node_hostname(self, host):
        """Get node hostname

        Args:
            host (str): Hostname

        Returns:
            str: Host hostname
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

    def stop_manager(self, host, systemd=False):
        """Stop manager

        Args:
            host (Hostname): Hostname
            systemd (bool, optional): Use systemd. Defaults to False.
        """
        pass

    def start_agent(self, host, systemd=False):
        """Start agent

        Args:
            host (str): Hostname
            systemd (bool, optional): Use systemd. Defaults to False.
        """
        pass

    def start_agents(self, agent_list):
        """Start agents

        Args:
            agent_list (list): Agents list
        """
        pass

    def start_manager(self, host, systemd=False):
        """Start manager

        Args:
            host (str): Hostname
            systemd (bool, optional): Use systemd. Defaults to False.
        """
        pass

    def start_managers(self, manager_list):
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
        pass
