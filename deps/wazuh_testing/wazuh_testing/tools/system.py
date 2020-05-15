# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import tempfile
import xml.dom.minidom as minidom

import testinfra
import yaml

from wazuh_testing.tools import WAZUH_CONF
from wazuh_testing.tools.configuration import set_section_wazuh_conf


class HostManager:
    """This class is an extensible remote host management interface. Within this we have multiple functions to modify
    the remote hosts depending on what our tests need.
    """

    def __init__(self, inventory_path: str):
        """Constructor of host manager class.

        Parameters
        ----------
        inventory_path : str
            Ansible inventory path
        """
        self.inventory_path = inventory_path

    def get_host(self, host: str):
        """Get the Ansible object for communicating with the specified host.

        Parameters
        ----------
        host : str
            Hostname

        Returns
        -------
        testinfra.modules.base.Ansible
            Host instance from hostspec
        """
        return testinfra.get_host(f"ansible://{host}?ansible_inventory={self.inventory_path}")

    def move_file(self, host: str, src_path: str, dest_path: str = '/var/ossec/etc/ossec.conf', check: bool = False):
        """Move from src_path to the desired location dest_path for the specified host.

        Parameters
        ----------
        host : str
            Hostname
        src_path : str
            Source path
        dest_path :
            Destination path
        check : bool
            Ansible check mode("Dry Run")(https://docs.ansible.com/ansible/latest/user_guide/playbooks_checkmode.html),
            by default it is enabled so no changes will be applied
        """
        self.get_host(host).ansible("copy", f"src={src_path} dest={dest_path} owner=ossec group=ossec mode=0775",
                                    check=check)

    def add_block_to_file(self, host: str, path: str, replace: str, before: str, after, check: bool = False):
        """Add text block to desired file.

        Parameters
        ----------
        host : str
            Hostname
        path : str
            Path of the file
        replace : str
            Text to be inserted in the file
        before : str
            Lower stop of the block to be replaced
        after : str
            Upper stop of the block to be replaced
        check : bool
            Ansible check mode("Dry Run")(https://docs.ansible.com/ansible/latest/user_guide/playbooks_checkmode.html),
            by default it is enabled so no changes will be applied
        """
        replace = f'{after}{replace}{before}'
        self.get_host(host).ansible("replace", f"path={path} regexp='{after}[\s\S]+{before}' replace='{replace}'",
                                    check=check)

    def control_service(self, host: str, service: str = 'wazuh', state: str = "started", check: bool = False):
        """Control the specified service.

        Parameters
        ----------
        host : str
            Hostname
        service : str
            Service to be controlled
        state : str
            Final state in which service must end
        check : bool
            Ansible check mode("Dry Run")(https://docs.ansible.com/ansible/latest/user_guide/playbooks_checkmode.html),
            by default it is enabled so no changes will be applied
        """
        if service == 'wazuh':
            service = 'wazuh-agent' if 'agent' in host else 'wazuh-manager'
        self.get_host(host).ansible("service", f"name={service} state={state}", check=check)

    def clear_file(self, host: str, file_path: str, check: bool = False):
        """Truncate the specified file.

        Parameters
        ----------
        host : str
            Hostname
        file_path : str
            File path to be truncated
        check : bool
            Ansible check mode("Dry Run")(https://docs.ansible.com/ansible/latest/user_guide/playbooks_checkmode.html),
            by default it is enabled so no changes will be applied
        """
        self.get_host(host).ansible("copy", f"dest={file_path} content='' force=yes", check=check)

    def get_file_content(self, host: str, file_path: str):
        """Get the content of the specified file.

        Parameters
        ----------
        host : str
            Hostname
        file_path : str
            Path of the file
        """
        return self.get_host(host).file(file_path).content_string

    def apply_config(self, config_yml_path: str, dest_path: str = WAZUH_CONF,
                     clear_files: list = None, restart_services: list = None):
        """Apply the configuration describe in the config_yml_path to the environment.

        Parameters
        ----------
        config_yml_path : str
            Path to the yml file that contains the configuration to be applied
        dest_path : str
            Destination file
        clear_files : list
            List of files to be truncated
        restart_services : list
            List of services to be restarted
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
            tmp_file = tempfile.NamedTemporaryFile()
            tmp_file.write(configuration.encode())
            tmp_file.seek(0)
            self.move_file(host, tmp_file.name, dest_path)
            tmp_file.close()

            if restart_services:
                for service in restart_services:
                    self.control_service(host=host, service=service, state='restarted')
            if clear_files:
                for log in clear_files:
                    self.clear_file(host=host, file_path=log)
