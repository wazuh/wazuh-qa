# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import json
import tempfile
import xml.dom.minidom as minidom

import testinfra
import yaml
from wazuh_testing.tools import WAZUH_CONF, WAZUH_API_CONF, API_LOG_FILE_PATH
from wazuh_testing.tools.configuration import set_section_wazuh_conf


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

    def get_host(self, host: str):
        """Get the Ansible object for communicating with the specified host.

        Args:
            host (str): Hostname

        Returns:
            testinfra.modules.base.Ansible: Host instance from hostspec
        """
        return testinfra.get_host(f"ansible://{host}?ansible_inventory={self.inventory_path}")

    def move_file(self, host: str, src_path: str, dest_path: str = '/var/ossec/etc/manager.conf', check: bool = False):
        """Move from src_path to the desired location dest_path for the specified host.

        Args:
        host (str): Hostname
        src_path (str): Source path
        dest_path (str): Destination path
        check (bool, optional): Ansible check mode("Dry Run")(https://docs.ansible.com/ansible/latest/user_guide/playbooks_checkmode.html), by default it is enabled so no changes will be applied. Default `False`
        """
        self.get_host(host).ansible("copy", f"src={src_path} dest={dest_path} owner=ossec group=ossec mode=0775",
                                    check=check)

    def add_block_to_file(self, host: str, path: str, replace: str, before: str, after, check: bool = False):
        """Add text block to desired file.

        Args:
            host (str): Hostname
            path (str): Path of the file
            replace (str): Text to be inserted in the file
            before (str): Lower stop of the block to be replaced
            after (str): Upper stop of the block to be replaced
            check (bool, optional): Ansible check mode("Dry Run")(https://docs.ansible.com/ansible/latest/user_guide/playbooks_checkmode.html), by default it is enabled so no changes will be applied. Default `False`
        """
        replace = f'{after}{replace}{before}'
        self.get_host(host).ansible("replace", f"path={path} regexp='{after}[\s\S]+{before}' replace='{replace}'",
                                    check=check)

    def modify_file_content(self, host: str, path: str = None, content: str = ''):
        tmp_file = tempfile.NamedTemporaryFile()
        tmp_file.write(content.encode())
        tmp_file.seek(0)
        self.move_file(host, src_path=tmp_file.name, dest_path=path)
        tmp_file.close()

    def control_service(self, host: str, service: str = 'wazuh', state: str = "started", check: bool = False):
        """Control the specified service.

        Args:
            host (str): Hostname
            service (str): Service to be controlled
            state (str): Final state in which service must end
            check (bool, optional): Ansible check mode("Dry Run")(https://docs.ansible.com/ansible/latest/user_guide/playbooks_checkmode.html), by default it is enabled so no changes will be applied. Default `False`
        """
        if service == 'wazuh':
            service = 'wazuh-agent' if 'agent' in host else 'wazuh-manager'
        self.get_host(host).ansible("service", f"name={service} state={state}", check=check)

    def clear_file(self, host: str, file_path: str, check: bool = False):
        """Truncate the specified file.

        Args:
            host (str): Hostname
            file_path (str): File path to be truncated
            check (bool, optional): Ansible check mode("Dry Run")(https://docs.ansible.com/ansible/latest/user_guide/playbooks_checkmode.html), by default it is enabled so no changes will be applied. Default `False`
        """
        self.get_host(host).ansible("copy", f"dest={file_path} content='' force=yes", check=check)

    def get_file_content(self, host: str, file_path: str):
        """Get the content of the specified file.

        Args:
            host (str): Hostname
            file_path (str) : Path of the file
        """
        return self.get_host(host).file(file_path).content_string

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
            template_manager_conf = self.get_file_content(host, dest_path).split('\n')
            parse_configurations[host] = set_section_wazuh_conf(sections=payload['sections'],
                                                                template=template_manager_conf)

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
            api_config (str,dict): Configuration to be applied. If it is a string, it will try to load the YAML in that path. If it is a dictionary, it will apply that configuration to every host in `host_list`.
            host_list (list, optional): List of hosts to apply the configuration in. Default `None`
            dest_path (str, optional): Path where the API configuration is. Default `/var/ossec/api/configuration/api.yaml`
            clear_log (bool, optional): Boolean to decide if it must truncate the 'api.log' after restarting the API or not.
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
            check (bool, optional): Ansible check mode("Dry Run")(https://docs.ansible.com/ansible/latest/user_guide/playbooks_checkmode.html),
                by default it is enabled so no changes will be applied. Default `False`

        Returns:
            API token (str): Usable API token.
        """
        if auth_context is not None:
            login_endpoint = '/security/user/authenticate/run_as'
            login_method = 'POST'
            login_body = 'body="{}"'.format(json.dumps(auth_context).replace('"', '\\"').replace(' ', ''))
        else:
            login_endpoint = '/security/user/authenticate'
            login_method = 'GET'
            login_body = ''

        try:
            token_response = self.get_host(host).ansible('uri', f'url=https://localhost:{port}{login_endpoint} '
                                                                f'user={user} password={password} method={login_method} '
                                                                f'{login_body} validate_certs=no force_basic_auth=yes',
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
            check ( bool, optional): Ansible check mode("Dry Run")(https://docs.ansible.com/ansible/latest/user_guide/playbooks_checkmode.html), by default it is enabled so no changes will be applied. Default `False`

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
            check (bool, optional): Ansible check mode("Dry Run")(https://docs.ansible.com/ansible/latest/user_guide/playbooks_checkmode.html), by default it is enabled so no changes will be applied. Default `False`

        Returns:
            stdout (str): The output of the command execution.
        """
        return self.get_host(host).ansible("command", cmd, check=check)["stdout"]
