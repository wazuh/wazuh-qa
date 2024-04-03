# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
from pathlib import Path

from modules.generic.utils import Utils
from modules.provision.actions import Action
from modules.provision.utils import logger
from modules.provision.models import InputPayload, ComponentInfo


PATH_BASE_DIR = Path(__file__).parents[2]


class Provision:
    """
    Provision class to install and uninstall components.

    Attributes:
        components (list[ComponentInfo]): List of components to install or uninstall.
        ansible_data (dict): Ansible data to render the playbooks.
        summary (dict): Summary of the provision.
    """

    def __init__(self, payload: InputPayload):
        """
        Initialize the provision.

        Args:
            payload (InputPayload): Payload with the provision information.
        """
        self.summary = {}

        self.action = 'install' if payload.install else 'uninstall'
        self.components = self.get_components(payload)
        self.ansible_data = self.__load_ansible_data(payload.inventory)

    def run(self) -> None:
        """
        Run the provision.
        """
        logger.info(f'Initiating provisionment.')

        logger.debug(f'Running action {self.action} for components: {self.components}')
        for component in self.components:
            try:
                logger.info(f'Provisioning "{component.component}"...')
                self.__provision(component)
                logger.info(f'Provision of "{component.component}" complete successfully.')
            except Exception as e:
                logger.error(f'Error while provisioning "{component.component}": {e}')
                raise
        logger.info('All components provisioned successfully.')
        logger.debug(f'Provision summary: {self.summary}')

    def get_components(self, payload: InputPayload) -> list[ComponentInfo]:
        """
        Validate the component and adds its dependency IP if required.

        Args:
            payload (InputPayload): Payload with the provision information.

        Returns:
            list[ComponentInfo]: List of components with the dependency IP.
        """
        components = payload.install or payload.uninstall
        dependencies = self.__get_deps_ips(payload.dependencies)
        # Check each component and add the dependency IP if required
        for component in components:
            component.dependencies = dependencies
            self.__validate_component_deps(component)
        return components

    def update_status(self, status: dict) -> None:
        """
        Update the status of the provision.

        Args:
            status (dict): The status of the executed action.
        """
        self.summary.update(status.stats)

    def __provision(self, component: ComponentInfo) -> None:
        """
        Provision the components.

        Args:
            component (ComponentInfo): Component to provision.
        """
        action = Action(self.action, component, self.ansible_data)
        status = action.execute()
        self.update_status(status)

    def __load_ansible_data(self, inventory: str | Path) -> dict:
        """
        Load the ansible data from the inventory file.

        Args:
            inventory (str | Path): Path to the inventory file.

        Returns:
            dict: Ansible data to render the playbooks.
        """
        try:
            return Utils.load_from_yaml(inventory)
        except FileNotFoundError:
            logger.error(f'Inventory file "{inventory}" not found.')
            raise
        except Exception as e:
            logger.error(f'Error loading inventory file "{inventory}": {e}')
            raise

    def __get_deps_ips(self, dependencies: dict) -> dict | None:
        """
        Get the list of dependencies IPs from reading each dependency`s
        inventory file and returning its ansible_host as IP.
        
        Args:
            dependencies (list[dict]): List of dependencies.
            
        Returns:
            dict: Dictionary with the dependencies IPs.
        """
        if not dependencies:
            return
        dependencies_ips = {}
        for key, value in dependencies.items():
            try:
                inventory = Path(value)
                if not inventory.exists():
                    raise FileNotFoundError(f'Inventory file "{inventory}" not found.')
                dep_ip = Utils.load_from_yaml(inventory, specific_key='ansible_host')
                dependencies_ips[key] = dep_ip
            except Exception as e:
                logger.error(f'Error getting dependency IP: {e}')
                raise
        return dependencies_ips
    
    def __validate_component_deps(self, component: ComponentInfo) -> None:
        """
        Validate the component dependencies.

        Args:
            component (ComponentInfo): Component to validate.
        """
        name = component.component
        dependencies = component.dependencies or {}
        # Dependencies validations.
        if name == 'wazuh-agent' and not dependencies.get('manager'):
            raise ValueError('Dependency IP is required to install Wazuh Agent.')
        logger.debug(f"Setting dependencies: {dependencies} for {name} component.")
