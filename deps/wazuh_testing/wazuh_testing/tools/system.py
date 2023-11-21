# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import tempfile
import xml.dom.minidom as minidom
from typing import Union
import testinfra
import yaml

from wazuh_testing.tools import WAZUH_CONF, WAZUH_API_CONF, API_LOG_FILE_PATH, WAZUH_LOCAL_INTERNAL_OPTIONS
from wazuh_testing.tools.configuration import set_section_wazuh_conf
from ansible.inventory.manager import InventoryManager
from ansible.parsing.dataloader import DataLoader
from ansible.vars.manager import VariableManager

class HostManager:
    """This class is an extensible remote host management interface. Within this we have multiple functions to modify
    the remote hosts depending on what our tests need.
    """

    def __init__(self, inventory_path: str):
        """Constructor of host manager class.

        Args:
            inventory_path (str): Ansible inventory path
        """
        self.inventory_path = inventory_path
        try:
            with open(self.inventory_path, "r") as inventory:
                self.inventory = yaml.safe_load(inventory.read())
        except (OSError, yaml.YAMLError) as inventory_err:
            raise ValueError(f"Could not open/load Ansible inventory '{self.inventory_path}': {inventory_err}")


        data_loader = DataLoader()
        self.inventory_manager = InventoryManager(loader=data_loader, sources=inventory_path)
        self.hosts_variables = {}

        variable_manager = VariableManager(loader=data_loader, inventory=self.inventory_manager)

        for host in self.inventory_manager.get_hosts():
            self.hosts_variables[host] = variable_manager.get_vars(host=self.inventory_manager.get_host(str(host)))


    def get_inventory(self) -> dict:
        """Get the loaded Ansible inventory.

        Returns:
            self.inventory: Ansible inventory
        """
        return self.inventory

    def get_inventory_path(self) -> str:
        """Get the loaded Ansible inventory.

        Returns:
            self.inventory: Ansible inventory
        """
        return self.inventory_path

    def get_group_hosts(self, pattern='None'):
        """Get all hosts from inventory that belong to a group.

        Args:
            group (str): Group name

        Returns:
            list: List of hosts
        """
        if pattern:
            return [str(host) for host in self.inventory_manager.get_hosts(pattern=pattern)]
        else:
            return [str(host) for host in self.inventory_manager.get_hosts()]


    def get_host_groups(self, host):
        """
        """
        group_list = self.inventory_manager.get_host(host).get_groups()
        return [str(group) for group in group_list]

    def get_host_variables(self, host):
        """Get the variables of the specified host.

        Args:
            host (str): Hostname

        Returns:
            testinfra.modules.base.Ansible: Host instance from hostspec
        """
        inventory_manager_host = self.inventory_manager.get_host(host)

        return self.hosts_variables[inventory_manager_host]

    def get_host(self, host: str):
        """Get the Ansible object for communicating with the specified host.

        Args:
            host (str): Hostname

        Returns:
            testinfra.modules.base.Ansible: Host instance from hostspec
        """
        return testinfra.get_host(f"ansible://{host}?ansible_inventory={self.inventory_path}")

    def truncate_file(self, host: str, filepath: str):
        ansible_command = 'file'
        if 'os_name' in self.get_host_variables(host):
            host_os_name = self.get_host_variables(host)['os_name']
            ansible_command = 'win_copy' if self.get_host_variables(host)['os_name'] == 'windows' else 'copy'

        result = self.get_host(host).ansible(ansible_command, f"dest='{filepath}' content=''", check=False)


    def move_file(self, host: str, src_path: str, dest_path: str = '/var/ossec/etc/ossec.conf', check: bool = False):
        """Move from src_path to the desired location dest_path for the specified host.

        Args:
        host (str): Hostname
        src_path (str): Source path
        dest_path (str): Destination path
        check (bool, optional): Ansible check mode("Dry Run"), by default it is enabled so no changes will be applied.
        """
        system = 'linux'
        if 'os_name' in self.get_host_variables(host):
            host_os_name = self.get_host_variables(host)['os_name']
            if host_os_name == 'windows':
                system = 'windows'

        if system == 'linux':
            a = self.get_host(host).ansible("copy", f"src={src_path} dest={dest_path} owner=wazuh group=wazuh mode=0644",
                                        check=check)
            print(a)
        else:
            self.get_host(host).ansible("ansible.windows.win_copy", f"src='{src_path}' dest='{dest_path}'", check=check)

    def add_block_to_file(self, host: str, path: str, replace: str, before: str, after, check: bool = False):
        """Add text block to desired file.

        Args:
            host (str): Hostname
            path (str): Path of the file
            replace (str): Text to be inserted in the file
            before (str): Lower stop of the block to be replaced
            after (str): Upper stop of172.31.6.71 the block to be replaced
            check (bool, optional): Ansible check mode("Dry Run"), by default it is enabled so no changes will be
                applied. Default `False`.
        """
        replace = f'{after}{replace}{before}'
        self.get_host(host).ansible("replace", fr"path={path} regexp='{after}[\s\S]+{before}' replace='{replace}'",
                                    check=check)

    def modify_file_content(self, host: str, path: str = None, content: Union[str, bytes] = ''):
        """Create a file with a specified content and copies it to a path.

        Args:
            host (str): Hostname
            path (str): path for the file to create and modify
            content (str, bytes): content to write into the file
        """
        tmp_file = tempfile.NamedTemporaryFile()
        tmp_file.write(content if isinstance(content, bytes) else content.encode())
        tmp_file.seek(0)
        self.move_file(host, src_path=tmp_file.name, dest_path=path)

        tmp_file.close()

    def control_service(self, host: str, service: str = 'wazuh', state: str = "started", check: bool = False):
        """Control the specified service.

        Args:
            host (str): Hostname
            service (str): Service to be controlled
            state (str): Final state in which service must end
            check (bool, optional): Ansible check mode("Dry Run"), by default it is enabled so no changes will be
                applied. Default `False`.
        """
        if service == 'wazuh':
            service = 'wazuh-agent' if 'agent' in host else 'wazuh-manager'
        self.get_host(host).ansible("service", f"name={service} state={state}", check=check)

    def clear_file(self, host: str, file_path: str, check: bool = False):
        """Truncate the specified file.

        Args:
            host (str): Hostname
            file_path (str): File path to be truncated
            check (bool, optional): Ansible check mode("Dry Run"), by default it is enabled so no changes will be
                applied. Default `False`
        """
        self.get_host(host).ansible("copy", f"dest={file_path} content='' force=yes", check=check)

    def clear_file_without_recreate(self, host: str, file_path: str, check: bool = False):
        """Truncate the specified file without recreating it.

        Args:
            host (str): Hostname
            file_path (str): File path to be truncated
            check (bool, optional): Ansible check mode("Dry Run"), by default it is enabled so no changes will be
                applied. Default `False`
        """
        self.get_host(host).ansible('shell', f"truncate -s 0 {file_path}", check=check)

    def get_file_content(self, host: str, file_path: str):
        """Get the content of the specified file.

        Args:
            host (str): Hostname
            file_path (str) : Path of the file
        """
        # return self.get_host(host).file(file_path).content_string
        ansible_method = 'command'
        command = 'cat'
        if 'os_name' in self.get_host_variables(host) and self.get_host_variables(host)['os_name'] == 'windows':
            ansible_method = 'win_shell'
            command = 'type'

        result = self.get_host(host).ansible(ansible_method, f"{command} '{file_path}'", check=False)

        return result['stdout']


        # testinfra_host = self.get_host(host)
        # result = testinfra_host.ansible("slurp", f"src='{file_path}'", check=False)
        # print(result)
        # if 'content' not in result:
        #     raise Exception(f"No content value in {result}")

        # decoded = base64.b64decode(result['content']).decode('utf-8')
        # return decoded


    def apply_config(self, config_yml_path: str, dest_path: str = WAZUH_CONF, clear_files: list = None,
                     restart_services: list = None):
        """Apply the configuration described in the config_yml_path to the environment.

        Args:
            config_yml_path (str): Path to the yml file that contains the configuration to be applied
            dest_path (str): Destination file
            clear_files (list): List of files to be truncated
            restart_services (list): List of services to be restarted
        """
        with open(config_yml_path, mode='r') as config_yml:
            config = yaml.safe_load(config_yml)

        parse_configurations = dict()
        for host, payload in config.items():
            template_ossec_conf = self.get_file_content(host, dest_path).split('\n')
            parse_configurations[host] = set_section_wazuh_conf(sections=payload['sections'],
                                                                template=template_ossec_conf)

        for host, configuration in parse_configurations.items():
            configuration = ''.join(configuration)
            dom = minidom.parseString(configuration)
            configuration = dom.toprettyxml().split('\n', 1)[1]
            self.modify_file_content(host, dest_path, configuration)

            if restart_services:
                for service in restart_services:
                    self.control_service(host=host, service=service, state='restarted')
            if clear_files:
                for log in clear_files:
                    self.clear_file(host=host, file_path=log)

    def apply_api_config(self, api_config: str or dict = None, host_list: list = None, dest_path: str = WAZUH_API_CONF,
                         clear_log: bool = False):
        """Apply the API configuration described in the yaml file or in the dictionary.

        Args:
            api_config (str,dict): Configuration to be applied. If it is a string, it will try to load the YAML in that
                path. If it is a dictionary, it will apply that configuration to every host in `host_list`.
            host_list (list, optional): List of hosts to apply the configuration in. Default `None`
            dest_path (str, optional): Path where the API configuration is.
            clear_log (bool, optional): Boolean to decide if it must truncate the 'api.log' after restarting the API.
        """
        if isinstance(api_config, str):
            with open(api_config, 'r') as config_yml:
                configuration = yaml.safe_load(config_yml)
        else:
            assert host_list is not None, f'"host_list" cannot be None if "api_config" is a dict.'
            configuration = {host: api_config for host in host_list}

        for host, config in configuration.items():
            self.modify_file_content(host, path=dest_path, content=yaml.dump("" if config is None else config))

        for host in host_list:
            self.control_service(host=host, service='wazuh-manager', state='restarted')
            if clear_log:
                self.clear_file(host=host, file_path=API_LOG_FILE_PATH)

    def get_api_token(self, host, user='wazuh', password='wazuh', auth_context=None, port=55000, check=False):
        """Return an API token for the specified user.

        Args:
            host (str): Hostname.
            user (str, optional): API username. Default `wazuh`
            password (str, optional): API password. Default `wazuh`
            auth_context (dict, optional): Authorization context body. Default `None`
            port (int, optional): API port. Default `55000`
            check (bool, optional): Ansible check mode("Dry Run"),
                by default it is enabled so no changes will be applied. Default `False`

        Returns:
            API token (str): Usable API token.
        """
        login_endpoint = '/security/user/authenticate'
        login_method = 'POST'
        login_body = ''
        if auth_context is not None:
            login_endpoint = '/security/user/authenticate/run_as'
            login_body = 'body="{}"'.format(json.dumps(auth_context).replace('"', '\\"').replace(' ', ''))

        try:
            token_response = self.get_host(host).ansible('uri', f"url=https://localhost:{port}{login_endpoint} "
                                                                f"user={user} password={password} "
                                                                f"method={login_method} {login_body} validate_certs=no "
                                                                f"force_basic_auth=yes",
                                                         check=check)
            return token_response['json']['data']['token']
        except KeyError:
            raise KeyError(f'Failed to get token: {token_response}')

    def make_api_call(self, host, port=55000, method='GET', endpoint='/', request_body=None, token=None, check=False):
        """Make an API call to the specified host.

        Args:
            host (str): Hostname.
            port (int, optional): API port. Default `55000`
            method (str, optional): Request method. Default `GET`
            endpoint (str, optional): Request endpoint. It must start with '/'.. Default `/`
            request_body ( dict, optional) : Request body. Default `None`
            token (str, optional):  Request token. Default `None`
            check ( bool, optional): Ansible check mode("Dry Run"), by default it is enabled so no changes will be
                applied. Default `False`

        Returns:
            API response (dict) : Return the response in JSON format.
        """
        request_body = 'body="{}"'.format(
            json.dumps(request_body).replace('"', '\\"').replace(' ', '')) if request_body else ''

        headers = {'Authorization': f'Bearer {token}'}
        if request_body:
            headers['Content-Type'] = 'application/json'

        return self.get_host(host).ansible('uri', f'url="https://localhost:{port}{endpoint}" '
                                                  f'method={method} headers="{headers}" {request_body} '
                                                  f'validate_certs=no', check=check)

    def run_command(self, host: str, cmd: str, check: bool = False):
        """Run a command on the specified host and return its stdout.

        Args:
            host (str) : Hostname
            cmd (str): Command to execute
            check (bool, optional): Ansible check mode("Dry Run"), by default it is enabled so no changes will be
                applied. Default `False`

        Returns:
            stdout (str): The output of the command execution.
        """
        return self.get_host(host).ansible("command", cmd, check=check)["stdout"]

    def run_shell(self, host: str, cmd: str, check: bool = False):
        """Run a shell command on the specified host and return its stdout.

        The difference with run_command is that here, shell symbols like &, |, etc. are interpreted.

        Args:
            host (str) : Hostname
            cmd (str): Shell command to execute
            check (bool, optional): Ansible check mode("Dry Run"), by default it is enabled so no changes will be
                applied. Default `False`

        Returns:
            stdout (str): The output of the command execution.
        """
        return self.get_host(host).ansible('shell', cmd, check=check)['stdout']

    def get_host_ip(self, host: str, interface: str):
        """Get the Ansible object for communicating with the specified host.
        Args:
            host (str): Hostname
        Returns:
            testinfra.modules.base.Ansible: Host instance from hostspec
        """
        return self.get_host(host).interface(interface).addresses

    def find_file(self, host: str, path: str, pattern: str = '*', use_regex: bool = False, recurse: bool = False,
                  file_type: str = 'file'):
        """Search and return information of a file inside a path.
        Args:
            host (str): Hostname
            path (str): Path in which to search for the file that matches the pattern.
            pattern (str): Restrict the files to be returned to those whose basenames match the pattern specified.
            use_regex (bool): If no, the patterns are file globs (shell), if yes, they are python regexes.
            recurse (bool): If target is a directory, recursively descend into the directory looking for files.
            file_type (str): Type of file to select. Choices are 'any', 'directory', 'file', 'link'.
        Returns:
            Files (list): List of found files.
        """
        return self.get_host(host).ansible("find", f"paths={path} patterns={pattern} recurse={recurse} "
                                                   f"use_regex={use_regex} file_type={file_type}")

    def get_stats(self, host: str, path: str):
        """Retrieve file or file system status.

        Args:
            host (str): Hostname.
            path (str): The full path of the file/object to get the facts of.

        Returns:
            Dictionary containing all the stat data.
        """
        return self.get_host(host).ansible("stat", f"path={path}")

    def configure_local_internal_options(self, local_internal_options: dict):
        """Add internal options in local_internal_options.conf

        Args:
            local_internal_options (dict): dictionary with hosts and internal options.
        """
        for target_host in local_internal_options:
            internal_options_data = []
            backup_local_internal_options = self.get_file_content(target_host, WAZUH_LOCAL_INTERNAL_OPTIONS)
            for internal_options in local_internal_options[target_host]:
                internal_options_data.append(f"{internal_options['name']}={internal_options['value']}\n")
            replace = backup_local_internal_options
            for internal_option in internal_options_data:
                replace = replace + internal_option
            self.modify_file_content(target_host, WAZUH_LOCAL_INTERNAL_OPTIONS, replace)

    def download_file(self, host, url, dest_path, mode='755'):
        """
        - name: Download foo.conf
            ansible.builtin.get_url:
            url: http://example.com/path/file.conf
            dest: /etc/foo.conf
            mode: '0440'
        """
        a = self.get_host(host).ansible("get_url", f"url={url} dest={dest_path} mode={mode}", check=False)
        return a

    def install_package(self, host, url, system='ubuntu'):
        result = False
        if system =='windows':
            a = self.get_host(host).ansible("win_package", f"path={url} arguments=/S", check=False)
            print(a)
        elif system == 'ubuntu':
            a = self.get_host(host).ansible("apt", f"deb={url}", check=False)
            if a['changed'] == True and a['stderr'] == '':
                result = True
            print(a)
        elif system == 'centos':
            a = self.get_host(host).ansible("yum", f"name={url} state=present sslverify=false disable_gpg_check=True", check=False)
            if 'rc' in a and a['rc'] == 0 and a['changed'] == True:
                result = True
            print(a)

    def get_master_ip(self):
        """

        """
        master_ip = None
        for manager in self.get_group_hosts('manager'):
            if 'type' in self.get_host_variables(manager) and \
                self.get_host_variables(manager)['type'] == 'master':
                master_ip = self.get_host_variables(manager)['ip']
        return master_ip

    def remove_package(self, host, package_name, system):
        result = False
        if system == 'windows':
            a = self.get_host(host).ansible("win_package", f"path={package_name} state=absent arguments=/S", check=False)
        elif system == 'ubuntu':
            a = self.get_host(host).ansible("apt", f"name={package_name} state=absent", check=False)
            if a['changed'] == True and a['stderr'] == '':
                result = True
        elif system == 'centos':
            a = self.get_host(host).ansible("yum", f"name={package_name} state=absent", check=False)
            if 'rc' in a and a['rc'] == 0 and a['changed'] == True:
                result = True
        return result

    def handle_wazuh_services(self, host, operation):
        os = self.get_host_variables(host)['os_name']
        binary_path = None
        if os == 'windows':
            if operation == 'restart':
                a = self.get_host(host).ansible('ansible.windows.win_shell', f'NET stop Wazuh', check=False)
                b = self.get_host(host).ansible('ansible.windows.win_shell', f'NET start Wazuh', check=False)

                print(a)
                print(b)
            else:
                a = self.get_host(host).ansible('ansible.windows.win_shell', f'NET {operation} Wazuh', check=False)
                print(a)
        else:
            if os == 'linux':
                binary_path = f"/var/ossec/bin/wazuh-control"
            elif os == 'macos':
                binary_path = f"/Library/Ossec/bin/wazuh-control"
            self.get_host(host).ansible('shell', f"{binary_path} {operation}", check=False)


def clean_environment(host_manager, target_files):
    """Clears a series of files on target hosts managed by a host manager
    Args:
        host_manager (object): a host manager object with not None inventory_path
        target_files (dict): a dictionary of tuples, each with the host and the path of the file to clear.
    """
    for target in target_files:
        host_manager.clear_file(host=target[0], file_path=target[1])
