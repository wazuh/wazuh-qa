# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import logging
import os
import sys
import tempfile
import xml.dom.minidom as minidom
import re

from threading import Thread
from typing import List, Union
from time import sleep

import testinfra
import yaml
from ansible.inventory.manager import InventoryManager
from ansible.parsing.dataloader import DataLoader
from ansible.vars.manager import VariableManager

from wazuh_testing.tools import (API_LOG_FILE_PATH, WAZUH_API_CONF, WAZUH_CONF,
                                 WAZUH_LOCAL_INTERNAL_OPTIONS)
from wazuh_testing.tools.configuration import set_section_wazuh_conf

logger = logging.getLogger('testinfra')
logger.setLevel(logging.CRITICAL)


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
            self.hosts_variables[str(host)] = variable_manager.get_vars(host=self.inventory_manager.get_host(str(host)))

    def get_inventory(self) -> dict:
        """Get the loaded Ansible inventory.

        Returns:
            self.inventory: Ansible inventory
        """
        return self.inventory

    def get_inventory_path(self) -> str:
        """Get the path of the loaded Ansible inventory.

        Returns:
            str: Path to the Ansible inventory file.

        Example:
            inventory_path = get_inventory_path()
        """
        return self.inventory_path

    def get_group_hosts(self, pattern='None'):
        """Get all hosts from the inventory that belong to a specified group pattern.

        Args:
            pattern (str, optional): Group name or pattern. Defaults to 'None'.

        Returns:
            list: List of host names belonging to the specified group pattern.

        Example:
            hosts = get_group_hosts('my_group')
        """
        if pattern:
            return [str(host) for host in self.inventory_manager.get_hosts(pattern=pattern)]
        else:
            return [str(host) for host in self.inventory_manager.get_hosts()]

    def get_host_groups(self, host):
        """Get the list of groups to which the specified host belongs.

        Args:
            host (str): Hostname.

        Returns:
            list: List of group names to which the host belongs.

        Example:
            groups = get_host_groups('my_host')
        """
        group_list = self.inventory_manager.get_host(host).get_groups()

        return [str(group) for group in group_list]

    def get_host_variables(self, host):
        """Get the variables of the specified host.

        Args:
            host (str): Hostname.

        Returns:
            testinfra.modules.base.Ansible: Host instance from hostspec.

        Example:
            variables = get_host_variables('my_host')
        """
        return self.hosts_variables[host]

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
            ansible_command = 'win_copy' if self.get_host_variables(host)['os_name'] == 'windows' else 'copy'

        result = self.get_host(host).ansible(ansible_command, f"dest='{filepath}' content=''", check=False)

        return result

    def move_file(self, host: str, src_path: str, dest_path: str = '/var/ossec/etc/ossec.conf', check: bool = False):
        """Move from src_path to the desired location dest_path for the specified host.

        Args:
            host (str): Hostname
            src_path (str): Source path
            dest_path (str): Destination path
            check (bool, optional): Ansible check mode("Dry Run"). Default `False`
        """
        result = None
        host_variables = self.get_host_variables(host)

        if 'os_name' in host_variables and host_variables['os_name'] == 'windows':
            result = self.get_host(host).ansible("ansible.windows.win_copy", f"src='{src_path}' dest='{dest_path}'",
                                                 check=check)
        else:
            result = self.get_host(host).ansible('copy', f'src={src_path} dest={dest_path} '
                                                 'owner=wazuh group=wazuh mode=preserve',
                                                 check=check)

        logging.info(f"File moved result {result}")

        return result

    def add_block_to_file(self, host: str, path: str, replace: str, before: str, after, check: bool = False):
        """Add text block to desired file.

        Args:
            host (str): Hostname
            path (str): Path of the file
            replace (str): Text to be inserted in the file
            before (str): Lower stop of the block to be replaced
            after (str): Upper stop of the block to be replaced
            check (bool, optional): Ansible check mode("Dry Run"), by default it is enabled so no changes will be
                applied. Default `False`.
        """
        replace = f'{after}{replace}{before}'
        self.get_host(host).ansible("replace", fr"path={path} regexp='{after}[\s\S]+{before}' replace='{replace}'",
                                    check=check)

    def modify_file_content(self, host: str, path: str = '', content: Union[str, bytes] = ''):
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
        ansible_method = 'command'
        command = 'cat'
        if 'os_name' in self.get_host_variables(host) and self.get_host_variables(host)['os_name'] == 'windows':
            ansible_method = 'win_shell'
            command = 'type'

        result = self.get_host(host).ansible(ansible_method, f"{command} '{file_path}'", check=False)

        return result['stdout']


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
            host (str): HostName in inventory.
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
            login_body = 'body="{}" body_format="json"'.format(
                json.dumps(auth_context).replace('"', '\\"').replace(' ', ''))

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

    def run_command(self, host: str, cmd: str, check: bool = False, system: str = 'linux'):
        """Run a command on the specified host and return its stdout.

        Args:
            host (str) : Hostname
            cmd (str): Command to execute
            check (bool, optional): Ansible check mode("Dry Run"), by default it is enabled so no changes will be
                applied. Default `False`
            system (str): The operating system type. Defaults to 'linux'.
                Supported values: 'windows', 'macos', 'linux'.

        Returns:
            stdout (str): The output of the command execution.
        """
        if system == 'windows':
            return self.get_host(host).ansible("win_command", cmd, check=check)
        else:
            return self.get_host(host).ansible("command", cmd, check=check)["stdout"]

    def run_shell(self, host: str, cmd: str, check: bool = False, system: str = 'linux'):
        """Run a shell command on the specified host and return its stdout.

        The difference with run_command is that here, shell symbols like &, |, etc. are interpreted.

        Args:
            host (str) : Hostname
            cmd (str): Shell command to execute
            check (bool, optional): Ansible check mode("Dry Run"), by default it is enabled so no changes will be
                applied. Default `False`
            system (str): The operating system type. Defaults to 'linux'.
                Supported values: 'windows', 'macos', 'linux'.

        Returns:
            stdout (str): The output of the command execution.
        """
        if system == 'windows':
            return self.get_host(host).ansible("win_shell", cmd, check=check)
        else:
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
                internal_options_data.append(f"\n{internal_options['name']}={internal_options['value']}\n")
            replace = backup_local_internal_options
            for internal_option in internal_options_data:
                replace = replace + internal_option
            self.modify_file_content(target_host, WAZUH_LOCAL_INTERNAL_OPTIONS, replace)

    def download_file(self, host, url, dest_path, mode='755'):
        """
        Downloads a file from the specified URL to the destination path on the specified host.

        Args:
            host (str): The target host on which to download the file.
            url (str): The URL of the file to be downloaded.
            dest_path (str): The destination path where the file will be saved on the host.
            mode (str, optional): The file permissions mode. Defaults to '755'.

        Returns:
            dict: Ansible result of the download operation.

        Example:
            host_manager.download_file('my_host', 'http://example.com/path/file.conf', '/etc/foo.conf', mode='0440')
        """
        result = self.get_host(host).ansible("get_url", f"url={url} dest={dest_path} mode={mode}", check=False)

        return result

    def install_package(self, host, url, system, retry=3, retry_delay=5):
        """
        Installs a package on the specified host.

        Args:
            host (str): The target host on which to install the package.
            url (str): The URL or name of the package to be installed.
            system (str, optional): The operating system type. Defaults to 'ubuntu'.
                Supported values: 'windows', 'ubuntu', 'centos'.

        Returns:
            Dict: Testinfra Ansible Response of the operation

        Example:
            host_manager.install_package('my_host', 'http://example.com/package.deb', system='ubuntu')
        """
        def install_msi_package(host, url):
            result = self.get_host(host).ansible("win_package",
                                                 f"path={url} arguments=/passive", check=False)

            return result

        def install_exe_package(host, url):
            result = self.get_host(host).ansible("win_package", f"path={url} arguments=/S", check=False)

            return result

        def install_apt_package(host, url):
            result = self.get_host(host).ansible("apt", f"deb={url}", check=False)

            return result

        def install_yum_package(host, url):
            result = self.get_host(host).ansible("yum", f"name={url} state=present "
                                                 'disable_gpg_check=True', check=False)
            return result

        def install_pkg_package(host, url):
            package_name = url.split('/')[-1]
            result = self.get_host(host).ansible("command", f"curl -LO {url}", check=False)
            cmd = f"installer -pkg {package_name} -target /"
            result = self.get_host(host).ansible("command", cmd, check=False)

            return result

        retry_installation_errors = [
            'This installation package could not be opened',
            'Could not get lock',
            'error: dpkg frontend lock was locked by another process with pid',
            'yum lockfile is held by another process'
        ]

        result = {}
        failed_installation = False

        extension = url.lower().split('.')[-1]

        system_supported = ['windows', 'ubuntu', 'centos', 'macos']
        installer_map = {
            'msi': install_msi_package,
            'exe': install_exe_package,
            'deb': install_apt_package,
            'rpm': install_yum_package,
            'pkg': install_pkg_package
        }

        if system not in system_supported:
            raise ValueError(f"Unsupported system: {system}")

        for _ in range(retry):
            installer_func = installer_map.get(extension, None)

            if not installer_func:
                raise ValueError(f"Unsupported extension: {extension} for {system}")

            result = installer_func(host, url)

            logging.debug(f"Package installation result {result}")
            failed_installation = not (result.get('changed', False) or result.get('rc') == 0) \
                or not (result.get('changed', False) or result.get('rc') == 0 or result.get('stderr', None) == '')

            if failed_installation:
                if not any(re.search(error, result.get('msg', '')) for error in retry_installation_errors) and \
                    not any(re.search(error, result.get('stderr', '')) for error in retry_installation_errors):
                    logging.error("Installation failed. Installation will not be retried.")
                    raise RuntimeError(f"Failed to install package in {host}: {result}")

                logging.error(f"Error installing {url} in {host}: Retrying installation...")

                sleep(retry_delay)
            else:
                break

        if failed_installation:
            raise RuntimeError(f"Failed to install package in {host}: {result}")

        return result

    def install_npm_package(self, host, url, system='ubuntu'):
        """
        Installs a package on the specified host using npm.

        Args:
            host (str): The target host on which to install the package.
            url (str): The URL or name of the package to be installed.
            system (str, optional): The operating system type. Defaults to 'ubuntu'.
                Supported values: 'windows', 'ubuntu', 'centos', 'macos'.

        Returns:
            Dict: Testinfra Ansible Response of the operation

        Example:
            host_manager.install_package('my_host', 'package_name', 'system_name')
        """

        # Define the npm install command
        cmd = f"npm install -g {url}"

        if system == 'macos':
            cmd = f"PATH=/usr/local/bin:$PATH {cmd}"
            shell_type = "shell"
        elif system == 'windows':
            shell_type = "win_shell"
        else:
            shell_type = "shell"

        # Execute the command and log the result
        result = self.get_host(host).ansible(shell_type, cmd, check=False)
        logging.info(f"npm package installed result {result}")

        return result

    def get_master_ip(self):
        """
        Retrieves the IP address of the master node from the inventory.

        Returns:
            str: The IP address of the master node, or None if not found.

        Example:
            master_ip = host_manager.get_master_ip()
        """
        master_ip = None

        for manager in self.get_group_hosts('manager'):
            if 'type' in self.get_host_variables(manager) and \
                    self.get_host_variables(manager)['type'] == 'master':
                master_ip = self.get_host_variables(manager)['ip']
                break

        return master_ip

    def get_master(self):
        """
        Retrieves the master node from the inventory.

        Returns:
            str: The master node, or None if not found.
        """
        master_node = None

        for manager in self.get_group_hosts('manager'):
            if 'type' in self.get_host_variables(manager) and \
                         self.get_host_variables(manager)['type'] == 'master':
                master_node = manager
                break
        if master_node is None:
            raise ValueError('Master node not found in inventory')

        return master_node

    def remove_package(self, host, system, package_uninstall_name=None, custom_uninstall_playbook=None):
        """
        Removes a package from the specified host.

        Args:
            host (str): The target host from which to remove the package.
            package_name (str): The name of the package to be removed.
            system (str): The operating system type.
                Supported values: 'windows', 'ubuntu', 'centos'.

        Returns:
            Dict: Testinfra Ansible Response of the operation

        Example:
            host_manager.remove_package('my_host', 'my_package', system='ubuntu')
        """
        logging.info(f"Removing package {package_uninstall_name} from host {host}")

        remove_operation_result = False

        os_name = self.get_host_variables(host)['os_name']

        if custom_uninstall_playbook:
            remove_operation_result = self.run_playbook(host, custom_uninstall_playbook)
        elif package_uninstall_name:
            if os_name == 'windows':
                remove_operation_result = self.get_host(host).ansible("win_package",
                                                                      f"product_id={package_uninstall_name} state=absent",
                                                                      check=False)
            elif os_name == 'linux':
                os = self.get_host_variables(host)['os'].split('_')[0]
                if os == 'centos':
                    remove_operation_result = self.get_host(host).ansible("yum",
                                                                          f"name={package_uninstall_name} state=absent",
                                                                          check=False)
                elif os == 'ubuntu':
                    remove_operation_result = self.get_host(host).ansible("apt",
                                                                          f"name={package_uninstall_name} state=absent",
                                                                          check=False)
            elif os_name == 'macos':
                remove_operation_result = self.get_host(host).ansible("command",
                                                                      f"brew uninstall {package_uninstall_name}",
                                                                      check=False)

        if not (remove_operation_result['changed'] or remove_operation_result.get('rc') == 0) \
            or not (remove_operation_result['changed'] or remove_operation_result.get('stderr', None) == ''):
            raise RuntimeError(f"Failed to remove package in {host}: {remove_operation_result}")

        logging.debug(f"Package removed result {remove_operation_result}")

        return remove_operation_result

    def remove_npm_package(self, host, system, package_uninstall_name=None, custom_uninstall_playbook=None):
        """
        Removes a package from the specified host using npm.

        Args:
            host (str): The target host from which to remove the package.
            package_name (str): The name of the package to be removed.
            system (str): The operating system type.
                Supported values: 'windows', 'ubuntu', 'centos', 'macos'.

        Returns:
            Dict: Testinfra Ansible Response of the operation

        Example:
            host_manager.remove_npm_package('my_host', 'system_name', 'package_name')
        """
        logging.info(f"Removing package {package_uninstall_name} from host {host}")
        logging.info(f"System: {system}")

        remove_operation_result = False

        os_name = self.get_host_variables(host)['os_name']

        if custom_uninstall_playbook:
            remove_operation_result = self.run_playbook(host, custom_uninstall_playbook)
        else:
            # Define the npm uninstall command
            cmd = f"npm uninstall -g {package_uninstall_name}"

            if system == 'macos':
                cmd = f"PATH=/usr/local/bin:$PATH {cmd}"
                shell_type = "shell"
            elif system == 'windows':
                shell_type = "win_shell"
            else:
                shell_type = "shell"

            # Execute the command and log the result
            remove_operation_result = self.get_host(host).ansible(shell_type, cmd, check=False)
            logging.info(f"npm package removed result {remove_operation_result}")

        return remove_operation_result

    def run_playbook(self, host, playbook_name, params=None):
        """
        Executes an Ansible playbook on the specified host.

        Args:
            host (str): The target host on which to execute the playbook.
            playbook_name (str): The name of the playbook to be executed.
            params (dict, optional): The parameters to be passed to the playbook. Defaults to None.

        Returns:
            Runner: The result of the playbook execution.

        Raises:
            ValueError: If the Python version is less than 3.7.
        """

        result = None

        if sys.version_info < (3, 7) or sys.platform.startswith("win"):
            raise ValueError("Python 3.7 or higher and a Unix-like system are required to run Ansible playbooks.")
        else:
            import ansible_runner

            file_dir = os.path.dirname(os.path.realpath(__file__))
            playbook_path = f"{file_dir}/playbooks/{playbook_name}.yaml"
            new_playbook = None
            new_playbook_path = None

            with open(playbook_path, 'r') as playbook_file:
                playbook = playbook_file.read()
                new_playbook = playbook.replace('HOSTS', host)

            temp_dir = tempfile.mkdtemp()
            new_playbook_path = f"{temp_dir}/playbook.yaml"

            with open(f"{temp_dir}/playbook.yaml", 'w') as playbook_file:
                playbook_file.write(new_playbook)

            try:
                result = ansible_runner.run(
                    inventory=self.inventory_path,
                    playbook=new_playbook_path,
                    host_pattern=host,
                    extravars=params,
                )
                logging.info("Ansible playbook executed successfully.")
            except Exception as e:
                logging.critical(f"Error executing Ansible playbook: {e}")

        return result

    def handle_wazuh_services(self, host, operation):
        """
        Handles Wazuh services on the specified host.

        Args:
            host (str): The target host on which to handle Wazuh services.
            operation (str): The operation to perform ('start', 'stop', 'restart').

        Example:
            host_manager.handle_wazuh_services('my_host', 'restart')
        """
        os = self.get_host_variables(host)['os_name']
        binary_path = None
        result = None

        if os == 'windows':
            if operation == 'restart':
                self.get_host(host).ansible('ansible.windows.win_shell', f'NET stop Wazuh', check=False)
                self.get_host(host).ansible('ansible.windows.win_shell', f'NET start Wazuh', check=False)
            else:
                result = self.get_host(host).ansible('ansible.windows.win_shell', f'NET {operation} Wazuh', check=False)
        else:
            if os == 'linux':
                result = binary_path = f"/var/ossec/bin/wazuh-control"
            elif os == 'macos':
                result = binary_path = f"/Library/Ossec/bin/wazuh-control"

            result = self.get_host(host).ansible('shell', f"{binary_path} {operation}", check=False)

        return result

    def control_environment(self, operation, group_list, parallel=False):
        """
        Controls the Wazuh services on hosts in the specified groups.

        Args:
            operation (str): The operation to perform on Wazuh services ('start', 'stop', 'restart').
            group_list (list): A list of group names whose hosts' Wazuh services should be controlled.

        Example:
            control_environment('restart', ['group1', 'group2'])
        """
        if parallel:
            threads = []
            for group in group_list:
                for host in self.get_group_hosts(group):
                    thread = Thread(target=self.handle_wazuh_services, args=(host, operation))
                    threads.append(thread)
                    thread.start()

            for thread in threads:
                thread.join()
        else:
            for group in group_list:
                for host in self.get_group_hosts(group):
                    self.handle_wazuh_services(host, operation)

    def get_agents_ids(self):
        """
        Retrieves the ID of the agents from the API.

        Args:
            agent_name (str): The name of the agent.

        Returns:
            str: The ID of the agent.
        """
        user, password = self.get_api_credentials()

        token = self.get_api_token(self.get_master(), user=user, password=password)
        agents = self.make_api_call(self.get_master(), endpoint='/agents/', token=token)['json']['data']

        agents_ids = []

        for agent in agents['affected_items']:
            if agent['id'] != '000':
                agents_ids.append(agent['id'])

        return agents_ids

    def get_api_credentials(self):
        default_user = 'wazuh'
        default_password = 'wazuh'

        master_variables = self.get_host_variables(self.get_master())

        user = master_variables.get('api_user', default_user)
        password = master_variables.get('api_password', default_password)

        return user, password

    def get_cluster_name(self):
        manager_list = self.get_group_hosts('manager')
        if not manager_list:
            raise ValueError("No manager is defined in the environment")

        first_manager_vars = self.inventory_manager.get_host(manager_list[0])
        cluster_name = first_manager_vars.vars.get('cluster_name', 'wazuh')

        return cluster_name

    def get_indexer_credentials(self):
        default_user = 'admin'
        default_password = 'changeme'

        try:
            indexer_variables = self.get_host_variables(self.get_group_hosts('indexer')[0])
        except IndexError:
            logging.critical("Indexer not found in inventory")
            raise

        user = indexer_variables.get('indexer_user', default_user)
        password = indexer_variables.get('indexer_password', default_password)

        return user, password

    def remove_agents(self):
        """
        Removes all the agents from the API.

        Args:
            host (str): The target host from which to remove the agent.

        Example:
            host_manager.remove_agent('my_host', 'my_agent_id')
        """
        user, password = self.get_api_credentials()

        token = self.get_api_token(self.get_master(), user=user, password=password)

        agents_ids = self.get_agents_ids()
        result = self.make_api_call(
            host=self.get_master(),
            method='DELETE',
            endpoint=f'/agents?agents_list={",".join(agents_ids)}&status=all&older_than=0s',
            token=token,
        )
        logging.info(f"Agents removed result {result}")

    def get_hosts_not_reachable(self) -> List[str]:
        """
        Checks that all hosts provided in the inventory are accessible.

        Returns:
            List[str]: List of hosts that are not reachable.
        """
        hosts_not_reachable = []
        for host in self.get_group_hosts('all'):
            logging.info(f"Checking host {host}...")
            os_name = self.get_host_variables(host)['os_name']
            if os_name == 'windows':
                command = 'ansible.windows.win_ping'
            else:
                command = 'ping'
            try:
                self.get_host(host).ansible(command, check=False)
            except Exception as e:
                logging.error(f"Error connecting to host {host}: {e}")
                hosts_not_reachable.append(host)

        return hosts_not_reachable

    def get_agents_summary_status(self, host):
        """
        Gets the agents summary status.

        Returns:
            result (str): Agents summary status returned by the API
        """
        token = self.get_api_token(host)
        result = self.make_api_call(
            host=host,
            method='GET',
            endpoint='/agents/summary/status',
            token=token,
        )

        return result['json']

    def clean_agents(self, restart_managers: bool = False) -> None:
        """Clean and register agents

        Args:
            host_manager (HostManager): An instance of the HostManager class.
            restart_managers (bool, optional): Whether to restart the managers. Defaults to False.
        """
        # Restart managers and stop agents
        logging.info("Stopping agents")
        self.control_environment("stop", ["agent"], parallel=True)

        logging.info("Removing agents")
        self.remove_agents()

        if restart_managers:
            logging.info("Restarting managers")
            self.control_environment("restart", ["manager"], parallel=True)


def clean_environment(host_manager, target_files):
    """Clears a series of files on target hosts managed by a host manager
    Args:
        host_manager (object): a host manager object with not None inventory_path
        target_files (dict): a dictionary of tuples, each with the host and the path of the file to clear.
    """
    for target in target_files:

        host_manager.clear_file(host=target[0], file_path=target[1])
