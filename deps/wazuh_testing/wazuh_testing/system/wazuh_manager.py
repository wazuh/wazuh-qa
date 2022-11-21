# Copyright (C) 2015-2022, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import os
import re
import yaml
from multiprocessing import Pool

from wazuh_testing.tools.configuration import set_section_wazuh_conf
from wazuh_testing.tools.system.host_manager import HostManager
from deps.wazuh_testing.wazuh_testing.api import make_api_call, get_api_details_dict

class WazuhEnvironment(HostManager):

    def __init__(self, inventory_path):
        super().__init__(inventory_path)

        # Map Wazuh files with methods to calculate path depending of OS
        self.common_environment_paths = {
            # Configurations files
            'ossec.conf': self.get_host_wazuh_main_configuration,
            'api.yaml': self.get_host_wazuh_api_configuration,
            'agent.conf': self.get_host_group_configuration,
            'internal_configuration.conf': self.get_host_local_internal_options,
            # Logs files
            'ossec.log': self.get_host_main_log,
            'api.log': self.get_host_wazuh_api_log,
            'cluster.log': self.get_host_wazuh_cluster_log,
            # Metadata
            'client.keys': self.get_host_client_keys
        }

    def get_file_path(self, host, filename, group=None):
        """Get the path of a file in a host
        Args:
            host (str): Hostname
            filename (str): File name
        Returns:
            str: Path of the file
        """
        custom_path = self.get_host_variables(host).get('wazuh_custom_path', None)
        os_name = self.get_host_variables(host).get('os_name')
        is_windows = os_name == 'windows'

        filepath = None

        if not custom_path:
            install_path = 'C:Program Files (x86)\\ossec-agent' if is_windows else '/var/ossec'
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

            filepath = os.path.join(install_path, 'etc', 'shared', group, 'agent.conf')

        elif filename == 'internal_configuration.conf':
            filepath = os.path.join(install_path, 'etc', 'internal_options.conf')

        return filepath

    def configure_host(self, host, configuration_host):
        """Configure ossec.conf, agent.conf, api.conf and local_internal_options of multiple hosts of the environment
        Configuration should fit the format expected for each configuration file:
        - ossec and agent.conf configuration should be provided as a list of configuration sections section.
        - local_internal_options configuration should be provided as a map
        - api.yaml shouls be provided as a map with desired configuration

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
        Args:
            host (str): Hostname
            configuration_host (Map): Map with new hosts configuration
        """
        print(f"Configuring hosts {host}")
        print(configuration_file)
        print("--------------------")
        operations_results = {host: {}}
        for configuration_file, configuration_values in configuration_host.items():
            # Get the configuration file path according to host OS
            host_configuration_file_path = self.get_host_configuration_file_path(host, configuration_file)
            print("HOst configuration file path {}".format(host_configuration_file_path))

            configuration_type = self.get_configuration_type(configuration_file)
            print("Configuration type")
            # agent.conf or ossec.conf
            if(configuration_type == 'main' or configuration_type == 'group'):
                print("Main")
                # Get current configuration
                current_configuration = self.get_file_content(host, host_configuration_file_path)
                print(f"Current configuration: {current_configuration}")
                # Using current configuration as a template, set configuration
                new_configuration = ''.join(set_section_wazuh_conf(configuration_values, current_configuration))
                print(new_configuration)
            elif configuration_type == 'internal_options':
                # Create local_internal_options file using specified map configuration
                new_configuration = self.create_local_internal_options_file(configuration_values)
            elif configuration_type == 'api':
                new_configuration = yaml.dump(configuration_values)
            else:
                # Otherwise, configuration will be considered as raw text
                new_configuration = str(configuration_values)

            operations_results[host][configuration_file] = self.modify_file_content(host, host_configuration_file_path,
                                                                              new_configuration,
                                                                              not self.is_windows(host), self.is_windows(host))
        for file, operation_result in operations_results[host].items():
            if 'msg' in operation_result:
                raise ValueError(f"Error during file operations in {host} for file {file}: {operation_result}")

        return operations_results

    def configure_environment(self, configuration_hosts, parallel=True):
        """Configure multiple hosts at the same time
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
        operations_results = None
        if parallel:
            host_configuration_map = [(host, configuration) for host, configuration in configuration_hosts.items()]
            pool = Pool()
            print("AAAAAAAAAAAAAaaaaaa")
            print(host_configuration_map)
            operations_results = pool.starmap(self.configure_host, host_configuration_map)
        else:
            operations_results = []
            for host, configurations in configuration_hosts.items():
                operations_results += self.configure_host(host,configurations)
        return operations_results

    def change_agent_configure_manager(self, agent_list , manager, calculate_manager_ip=True):
        """Change configured manager of specified agent

        Args:
            agent (str): Agent name
            manager (str): Manager name in the environment/Manager IP
            calculate_manager_ip(boolean): Enable manager ip calculation
        """
        configured_manager = self.get_host_ipv4(manager) if calculate_manager_ip else manager

        new_configuration = {}
        configuration = [{'section': 'client', 'elements': [{'server': {'elements':
                        [{'address': {'value': f"{configured_manager}"}}]}}]}]

        for agent in agent_list:
            new_configuration[agent] = {
                'ossec.conf': configuration
            }

        self.configure_environment(new_configuration)

    def get_wazuh_file_path(self, host):
        """Get filepath of a wazuh configuration or log file

        Args:
            host (str): Host name

        Returns:
            str: File path
        """
        wazuh_directory = ''
        host_attributes = self.get_host(host).ansible.get_variables()
        print(host_attributes)

        if 'custom_folder' in host_attributes:
            wazuh_directory = host_attributes['custom_folder']
        else:
            if (host_attributes['os_name'] == 'linux' or host_attributes['os_name'] == 'solaris'):
                wazuh_directory = os.path.join("/var", "ossec")
            elif (host_attributes['os_name'] == 'windows'):
                wazuh_directory = os.path.join('C:', '\\', 'Program Files (x86)', 'ossec-agent')
            else:
                wazuh_directory = os.path.join("/", "Library", "Ossec")
        return wazuh_directory

    def get_host_wazuh_main_configuration(self, host):
        """Return host ossec.conf configuration of specified host

        Args:
            host (str): Hostname

        Returns:
            str: Fullpath of host Wazuh main configuration
        """
        wazuh_directory = self.get_wazuh_file_path(host)
        host_attributes = self.get_host(host).ansible.get_variables()

        wazuh_main_configuration = ''

        if (host_attributes['os_name'] == 'linux' or host_attributes['os_name'] == 'solaris' or
            host_attributes['os_name'] == 'macos'):
            wazuh_main_configuration = os.path.join(wazuh_directory, 'etc', 'ossec.conf' )
        else:
            wazuh_main_configuration = os.path.join(wazuh_directory, 'ossec.conf' )

        return wazuh_main_configuration

    def get_host_wazuh_api_configuration(self, host):
        """Get filepath of wazuh api configuration file

        Args:
            host (str): Hostname

        Returns:
            str: Api configuration filepath
        """
        wazuh_directory = self.get_wazuh_file_path(host)
        api_configuration_path = os.path.join(wazuh_directory, 'api', 'configuration', 'api.yaml')
        return api_configuration_path

    def get_host_group_directory(self, host, group='default'):
        """Get filepath of group configuration file.

        In case the host is an agent, it will return /etc/shared directory

        Args:
            host (str): Hostname
            group (str, optional): Group name. Defaults to 'default'.

        Returns:
            str: Group shared configuration directory path
        """
        wazuh_directory = self.get_wazuh_file_path(host)
        directory_path = ''

        if host in self.get_agents():
            directory_path = os.path.join(wazuh_directory, 'etc', 'shared')
        else:
            directory_path = os.path.join(wazuh_directory, 'etc', 'shared', group)

        return directory_path

    def get_host_group_configuration(self, host, file='agent.conf', group='default'):
        """Get host group configuration file.

        Args:
            host (str): Hostname
            file (str, optional): Configuration filename. Defaults to 'agent.conf'.
            group (str, optional): Group name. Defaults to 'default'.

        Returns:
            str: Filepath of shared configuration file
        """
        return os.path.join(self.get_host_group_directory(host, group), file)

    def get_host_local_internal_options(self, host):
        """Get host local internal option filepath

        Args:
            host (str): Hostname

        Returns:
            str: Local internal option filepath
        """
        wazuh_directory = self.get_wazuh_file_path(host)
        host_attributes = self.get_host(host).ansible.get_variables()

        wazuh_local_internal_option = ''

        if (host_attributes['os_name'] == 'linux' or host_attributes['os_name'] == 'solaris' or
            host_attributes['os_name'] == 'macos'):
            wazuh_local_internal_option = os.path.join(wazuh_directory, 'etc', 'local_internal_options.conf' )
        else:
            wazuh_local_internal_option = os.path.join(wazuh_directory, 'local_internal_options.conf' )

        return wazuh_local_internal_option

    def get_host_main_log(self, host):
        """Get host ossec.log filepath

        Args:
            host (str): Hostname

        Returns:
            str: ossec.log filepath
        """
        wazuh_directory = self.get_wazuh_file_path(host)
        host_attributes = self.get_host(host).ansible.get_variables()

        wazuh_main_log_path = ''

        if (host_attributes['os_name'] == 'linux' or host_attributes['os_name'] == 'solaris' or
            host_attributes['os_name'] == 'macos'):
            wazuh_main_log_path = os.path.join(wazuh_directory, 'logs', 'ossec.log' )
        else:
            wazuh_main_log_path = os.path.join(wazuh_directory, 'ossec.log' )

        return wazuh_main_log_path

    def get_host_wazuh_api_log(self, host):
        """Get host api log filepath

        Args:
            host (str): Hostname

        Returns:
            str: Api log filepath
        """
        wazuh_directory = self.get_wazuh_file_path(host)

        wazuh_api_log = ''

        return os.path.join(wazuh_directory, 'logs', 'api.log')

    def get_host_wazuh_cluster_log(self, host):
        """Get host wazuh cluster log

        Args:
            host (str): Hostname

        Returns:
            str: Wazuh cluster log filepath
        """
        wazuh_directory = self.get_wazuh_file_path(host)

        wazuh_api_log = ''

        return os.path.join(wazuh_directory, 'logs', 'cluser.log')

    def get_host_client_keys(self, host):
        """Get host client keys file

        Args:
            host (str): Hostname

        Returns:
            str: Host client keys file
        """
        wazuh_directory = self.get_wazuh_file_path(host)
        host_attributes = self.get_host(host).ansible.get_variables()

        client_key = ''

        if (host_attributes['os_name'] == 'linux' or host_attributes['os_name'] == 'solaris' or
            host_attributes['os_name'] == 'macos'):
            client_key = os.path.join(wazuh_directory, 'etc', 'client.keys' )
        else:
            client_key = os.path.join(wazuh_directory, 'client.keys' )

        return client_key

    def get_configuration_type(self, configuration_name):
        """Get configuration filetype

        Args:
            configuration_name (str): Configuration filename

        Returns:
            str: Configuration filetype
        """
        configuration_type = ''
        if 'ossec.conf' in configuration_name:
            configuration_type = 'main'
        elif 'agent.conf' in configuration_name:
            configuration_type = 'group'
        elif 'api.yam' in configuration_name:
            configuration_type = 'api'
        elif 'local_internal.conf' in configuration_name:
            configuration_type = 'internal_options'
        else:
            configuration_type = 'other'

        return configuration_type

    def get_host_configuration_file_path(self, host, configuration_name):
        """Get host configuration filepath

        Args:
            host (str): Hostname

        Returns:
            str: Configuration filepath
        """
        wazuh_configuration_file = self.get_wazuh_file_path(host)
        host_attributes = self.get_host(host).ansible.get_variables()

        configuration_path = ''
        common_configuration = [key for key in self.common_environment_paths.keys() if key in configuration_name]
        extra_vars = []

        print(host)
        print(configuration_name)

        print(common_configuration)

        if common_configuration:
            configuration_file = configuration_name
            print(configuration_file)
            if ':' in configuration_name:
                configuration_name_split = configuration_name.split(':')[:]
                configuration_name = configuration_name_split[-1]
                extra_vars = configuration_name_split[:-1]
            if extra_vars:
                print("Extra vars")
                configuration_path = self.common_environment_paths[common_configuration[0]](host, configuration_name, *extra_vars)
            else:
                print("No extra vars")
                print(common_configuration[0])
                print(self.common_environment_paths[common_configuration[0]])
                print(host,configuration_name)
                self.get_host_wazuh_main_configuration(host, configuration_name)
                print("fdasfdas")
                configuration_path = self.common_environment_paths[common_configuration[0]](host, configuration_name)
        print(configuration_path)
        return configuration_path

    def create_local_internal_option_file(self, local_internal_options):
        """Create local internal options file string

        Args:
            local_internal_options (dict): Local internal options

        Returns:
            str: Local internal options file
        """
        local_internal_options_content = ''
        for option,value in local_internal_options.items():
                local_internal_options_file_content += f"{option}={value}\n"
        return local_internal_options_content

    def backup_configuration(self, configuration_list):
        """Backup configuration

        Args:
            configuration_list (dict): Host configuration files to backup

        Returns:
            dict: Host backup filepaths
        """
        backup_paths = {}
        for host, backup_files in configuration_list.items():
            backup_paths[host] = {}
            for file in backup_files:
                temporal_folder = '/tmp' if not self.is_windows(host) else 'C:\\Users\\qa\\AppData\Local\Temp'
                new_filename = os.path.join(temporal_folder, file + '.backup',)
                backup_paths[host][file] = new_filename

        return backup_paths

    def restore_backup_configuration(self, backup_configuration):
        """Restore backup configuration

        Args:
            backup_configuration (dict): Backup configuration filepaths
        """
        for host, backup_files in backup_configuration.items():
            for file, backup in backup_files.items():
                self.move_file(host=host, dest_path=self.get_host_configuration_file_path(host, file),
                               src_path=backup, remote_src=True, sudo=True)

    def log_search(self, host, pattern, timeout, file, escape=False, output_file='find.json'):
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
        pattern_join = "\"" + '" "'.join(pattern) + "\""
        timeout_join = ' '.join(timeout)
        file_join = ' '.join(file)

        output_command = self.run_shell(host, "search-pattern" + f' -p {pattern_join} '
                                              f'-t {timeout_join} -f {file_join} -o {output_file}',
                                              windows=self.is_windows(host))
        if output_command ['rc'] != 0:
            raise ValueError(output_command)
        elif not (self.get_host(host).file('find.json').exists):
            return None
        else:
            result = json.loads(self.get_file_content(host, output_file))
            return result

    def log_multisearch(self, multipattern_search, file='/var/ossec/logs/ossec.log', escape=False):
        """Multihost log pattern

        Args:
            multipattern_search (dict): Multihost and multipattern  dictionary
            escape (bool, optional): Escape special characters. Defaults to False.

        Raises:
            Exception: _description_
            Exception: _description_

        Returns:
            _type_: _description_
        """

        hosts_pattern_pool = Pool()

        pattern_search_parameters = []
        for host, parameters in multipattern_search:
            for parameter in parameters:
                pattern_search_parameters += [(host, parameter['regex'],
                                               str(parameter['timeout']),
                                               parameter['path'])]

        multisearch_results = hosts_pattern_pool.starmap(self.log_search, pattern_search_parameters)

        return multisearch_results

    def get_host_variables(self, host):
        """Get host variables_

        Args:
            host (str): Hostname

        Returns:
            dict: Host variables
        """
        return self.get_host(host).ansible.get_variables()

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

    def get_managers(self):
        """Get environment managers names

        Returns:
            List: Managers names list
        """
        environment_information = self.get_host_variables('all')
        return environment_information['groups'].get('manager', [])

    def get_agents(self):
        """Get environment agents names

        Returns:
            List: Agent names list
        """
        environment_information = self.get_host_variables('all')
        return environment_information['groups'].get('agent', [])

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

    def restart_agent(self, host, systemd=False):
        """Restart agent

        Args:
            host (str): Hostname
            systemd (bool, optional): Restart using systemd. Defaults to False.
        """
        command = ''
        if systemd and not self.is_windows(host):
            command = 'systemctl restart wazuh-agent'
        elif self.is_windows(host):
            command = 'net restart WazuhSvc'
        else:
            command =  f"{self.get_wazuh_file_path(host)}/bin/wazuh-control restart"

        self.run_command(host,command)

    def get_agents_info(self):
        """Get registered agents information.

        Returns:
            dict: Agent information
        """
        api_details = self.get_api_details()
        return self.make_api_call(method="GET", endpoint='/agents', headers=api_details['auth_headers']).json()

    def get_agents_id(self):
        """Get agents id

        Returns:
            List: Agents id list
        """
        agent_info_list = self.get_agents_info()['data']['affected_items']
        agent_ids = {}
        for agent in agent_info_list:
            agent_ids[agent['name']] = agent['id']
        return agent_ids

    def restart_agents(self, agent_list=None):
        """Restart list of agents

        Args:
            agent_list (list, optional): Agent list. Defaults to None.
        """
        agent_list = agent_list if agent_list else self.get_agents()
        pool = Pool()
        pool.map(self.restart_agent, agent_list)

    def restart_manager(self, host, systemd=False):
        """Restart manager

        Args:
            host (str): Hostname
            systemd (bool, optional): Use systemd. Defaults to False.
        """
        command = ''
        if systemd:
            command = 'systemctl restart wazuh-manager'
        else:
            command =  f"{self.get_wazuh_file_path(host)}/bin/wazuh-control restart"

        self.run_command(host,command)

    def restart_managers(self, manager_list):
        """Restart managers

        Args:
            manager_list (list): Managers list
        """
        manager_list = manager_list if manager_list else self.get_managers()
        pool = Pool()
        pool.map(self.restart_agent, manager_list)

    def stop_agent(self, host, systemd=False):
        """Stop agent

        Args:
            host (str): Hostname
            systemd (bool, optional): Use systemd. Defaults to False.
        """
        command = ''
        if systemd and not self.is_windows(host):
            command = 'systemctl stop wazuh-agent'
        elif self.is_windows(host):
            command = 'net stop WazuhSvc'
        else:
            command =  f"{self.get_wazuh_file_path(host)}/bin/wazuh-control stop"

        self.run_command(host, command)

    def stop_agents(self, agent_list=None):
        """Stop agents

        Args:
            agent_list(list, optional): Agents list. Defaults to None
        """
        agent_list = agent_list if agent_list else self.get_agents()
        pool = Pool()
        pool.map(self.stop_agent, agent_list)

    def get_master_node(self):
        """Get master manager hostname

        Returns:
            str: Manager master node
        """
        manager_list = self.get_managers()
        for manager in manager_list:
            manager_parameters = self.get_host_variables(manager)
            if 'type' in manager_parameters and manager_parameters['type'] == 'master':
                return manager

    def get_api_details(self):
        """Get api details

        Returns:
            dict: Api details
        """
        api_host = self.get_host_ipv4(self.get_master_node())
        return get_api_details_dict(host=api_host)


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
        master_ip = self.get_host_ipv4(self.get_master_node())
        return make_api_call(host=master_ip, port=port, method=method, endpoint=endpoint, headers=headers,
                             params=params,
                             request_json=request_body)

    def remove_file(self, host, file):
        """Remove file

        Args:
            host (str): Hostname
            file (str): File
        """
        ansible_command = 'win_file' if self.is_windows(host) else 'file'
        become = False if self.is_windows(host) else True
        command = f"path={file} state=absent"
        self.get_host(host).ansible(ansible_command, command, False, become)

    def create_file_structure(self, file_structure):
        pool = Pool()
        pool.starmap(self.create_file, zip(file_structure.keys(), file_structure.values()) )

    def get_node_hostname(self, host):
        """Get node hostname

        Args:
            host (str): Hostname

        Returns:
            str: Host hostname
        """
        return self.get_host(host).check_output('hostname')

    def clean_client_keys(self, hosts=None):
        """Clean client keys

        Args:
            hosts (str, optional): Hostname. Defaults to None.
        """
        agent_client_keys_file = {}
        hosts = hosts if hosts else self.get_agents()
        for host in hosts:
            agent_client_keys_file[host] = self.get_host_client_keys(host)

        pool = Pool()
        pool.starmap(self.remove_file, zip(agent_client_keys_file.keys(), agent_client_keys_file.values()) )

    def clean_agents(self, agents=None):
        """Stop agents, remove them from manager and clean their client keys

        Args:
            agents (_type_, agents_list): Agents list. Defaults to None.
        """
        # Stop agents
        self.stop_agents(agents)
        # Remove agents from manager
        self.remove_agents_from_manager(agents)
        # Remove agents metadata
        self.clean_client_keys(self.get_agents())

    def remove_agents_from_manager(self, agents=None, status='all', older_than='0s'):
        """Remove agents from manager

        Args:
            agents (list, optional): Agents list. Defaults to None.
            status (str, optional): Agents status. Defaults to 'all'.
            older_than (str, optional): Older than parameter. Defaults to '0s'.

        Returns:
            dict: API response
        """
        # Get agents ids
        master_ip = self.get_host_ipv4(self.get_master_node())
        agent_ids = list(self.get_agents_id().values())

        if '000' in agent_ids:
            agent_ids.remove('000')

        api_details = self.get_api_details()

        params = {'agents_list': agent_ids, 'status': status, 'older_than': older_than}

        return self.make_api_call(method="DELETE", endpoint='/agents', headers=api_details['auth_headers'],
                                  params=params)

    def stop_manager(self, host, systemd=False):
        """Stop manager

        Args:
            host (Hostname): Hostname
            systemd (bool, optional): Use systemd. Defaults to False.
        """

        command = ''
        if systemd:
            command = 'systemctl stop wazuh-manager'
        else:
            command =  f"{self.get_wazuh_file_path(host)}/bin/wazuh-control stop"

        self.run_command(host,command)

    def start_agent(self, host, systemd=False):
        """Start agent

        Args:
            host (str): Hostname
            systemd (bool, optional): Use systemd. Defaults to False.
        """
        command = ''
        if systemd and not self.is_windows(host):
            command = 'systemctl start wazuh-agent'
        elif self.is_windows(host):
            command = 'net start WazuhSvc'
        else:
            command =  f"{self.get_wazuh_file_path(host)}/bin/wazuh-control start"

        self.run_command(host,command)

    def start_agents(self, agent_list):
        """Start agents

        Args:
            agent_list (list): Agents list
        """
        agent_list = agent_list if agent_list else self.get_agents()
        pool = Pool()
        pool.map(self.start_agent, agent_list)

    def start_manager(self, host, systemd=False):
        """Start manager

        Args:
            host (str): Hostname
            systemd (bool, optional): Use systemd. Defaults to False.
        """
        command = ''
        if systemd:
            command = 'systemctl start wazuh-manager/'
        else:
            command =  f"{self.get_wazuh_file_path(host)}/bin/wazuh-control start"

        self.run_command(host,command)

    def start_managers(self, manager_list):
        """Start managers

        Args:
            manager_list (list): Managers list
        """
        manager_list = manager_list if manager_list else self.get_managers()
        pool = Pool()
        pool.map(self.start_manager, manager_list)

    def restart_environment(self, parallel=True):
        """Restart all agents and manager in the environment

        Args:
            parallel (bool, optional): _description_. Defaults to True.
        """
        environment_information = self.get_host_variables('all')
        managers = environment_information['groups'].get('manager', [])
        agents = environment_information['groups'].get('agent', [])


        if not parallel:
            # For all agent start_agent
            for manager in managers:
                self.restart_manager(manager)

            # For all agent start_agent
            for agent in agents:
                self.restart_agent(agent)
        else:
            managers_pool = Pool()
            managers_pool.map(self.restart_manager, [(manager,) for manager in managers])

            agents_pool = Pool()
            agents_pool.map(self.restart_agent, [(agent,) for agent in agents])

    def get_host_ipv4(self, host):
        """Get host IPV4

        Args:
            host (str): Hostname

        Returns:
            str: Host ipv4
        """
        return self.get_host_variables(host)['ip']
