# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
from modules.generic import Ansible

from modules.provision.handler import ProvisionHandler
from modules.provision.models import ComponentInfo
from modules.provision.utils import logger


class Action:
    """
    Class to define the action.

    Attributes:
        handler (ProvisionHandler): The provision handler.
        ansible (Ansible): The Ansible instance.
    """

    def __init__(self, action: str, component_info: ComponentInfo, ansible_data: dict) -> None:
        """
        Initialize the action.

        Args:
            action (str): The action to execute.
            component_info (ComponentInfo): The component information.
            ansible_data (dict): The Ansible data.
        """
        component_info = ComponentInfo(**dict(component_info))
        action_type = component_info.type
        self.handler = ProvisionHandler(component_info, action, action_type)
        self.ansible = Ansible(ansible_data, logger=logger, playbooks_path=self.handler.templates_path)

    def execute(self) -> dict:
        """
        Execute the action for the component.

        Returns:
            dict: The status of the executed action.
        """
        # Get the OS family variable.
        self.handler.variables_dict['ansible_os_family'] = self._get_os_family()
        # Render the playbook with the variables.
        logger.debug(f"Render playbook with vars: {self.handler.variables_dict}.")
        tasks = self.ansible.render_playbooks(self.handler.variables_dict)
        # Get and execute the playbook.
        logger.debug(f"Tasks to execute: {tasks}.")
        playbook = self._get_playbook(tasks)
        logger.info(f"Execute {self.handler.action} for {self.handler.component_info.component}.")
        status = self.ansible.run_playbook(playbook)

        return status

    def _get_os_family(self) -> str:
        """
        Get the OS family.

        Returns:
            str: The OS family.
        """
        ansible_task = [{
            'name': 'Capture ansible_os_family',
            'set_fact': {
                'ansible_os_family': "{{ ansible_facts['distribution_file_variety'] }}",
                'cacheable': 'yes'
            }
        }]
        logger.debug(f"Get OS family for {self.ansible.ansible_data.ansible_host}.")
        playbook = self._get_playbook(ansible_task)
        status = self.ansible.run_playbook(playbook)
        fact_cache = status.get_fact_cache(host=self.ansible.ansible_data.ansible_host)
        logger.debug(f"OS family: {fact_cache.get('ansible_os_family')}.")
        return fact_cache.get('ansible_os_family') or ''

    def _get_playbook(self, tasks: list[dict]) -> dict:
        """
        Get the playbook to execute.

        Returns:
            dict: The playbook to execute.
        """
        playbook = {
            'hosts': self.ansible.ansible_data.ansible_host,
            'become': True,
            'gather_facts': True,
            'tasks': tasks,
        }
        return playbook
