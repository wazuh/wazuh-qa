# Description: Provision module for Wazuh deployability
import subprocess
import sys

from pathlib import Path

from modules.generic.utils import Utils
from modules.provision.actions import Action
from modules.provision.logger import logger
from modules.provision.models import InputPayload, ComponentInfo
from modules.provision.provisionModule import ProvisionModule


PATH_BASE_DIR = Path(__file__).parents[2]


class Provision(ProvisionModule):
    """
    Provision class to install and uninstall components.

    Attributes:
        component_info (list[ComponentInfo]): List of components to install or uninstall.
        ansible_data (dict): Ansible data to render the playbooks.
        summary (dict): Summary of the provision.
    """

    def __init__(self, payload: InputPayload):
        """
        Initialize the provision.

        Args:
            payload (InputPayload): Payload with the provision information.
        """
        if payload.install:
            logger.debug("Installing components")
            self.component_info = payload.install
            self.action = "install"
        if payload.uninstall:
            logger.debug("Uninstalling components")
            self.component_info = payload.uninstall
            self.action = "uninstall"

        self.validate_component_ip(self.component_info, payload.manager_ip)
        self.ansible_data = Utils.load_from_yaml(
            payload.inventory,
            map_keys={
                'ansible_host': 'ansible_host',
                'ansible_user': 'ansible_user',
                'ansible_port': 'ansible_port',
                'ansible_ssh_private_key_file': 'ansible_ssh_private_key_file'
            }
        )
        self.summary = {}

    # -------------------------------------
    #   Methods
    # -------------------------------------

    def run(self) -> None:
        """
        Run the provision.
        """
        # self.node_dependencies()
        logger.debug(f"Provisioning components: {self.component_info}. With action: {self.action}")
        self.install_host_dependencies()

        for item in self.component_info:
            action_class = Action(self.action, item, self.ansible_data)
            status = action_class.execute()

            self.update_status(status)

        logger.info("Provision finished")
        logger.debug(f"Summary: {self.summary}")

    def validate_component_ip(self, components: list[ComponentInfo], ip: str) -> None:
        if not ip:
            return
        for component in components:
            if component.component == 'wazuh-agent':
                logger.debug(f"Setting dependency IP to {ip}")
                component.manager_ip = ip

    @staticmethod
    def node_dependencies() -> None:
        """
        Install python dependencies on Worker node.
        """
        venv_path = PATH_BASE_DIR / 'venv'
        if not venv_path.exists():
            subprocess.run(['python3', '-m', 'venv', str(venv_path)], check=True)

        logger.debug(f"Activating virtualenv {venv_path}")
        activate_script = venv_path / 'bin' / 'activate'
        command = f"source {activate_script}" if sys.platform != 'win32' else f"call {activate_script}"
        subprocess.run(command, shell=True, executable="/bin/bash")
        logger.debug("Upgrading pip.")
        subprocess.run(['python3', '-m', 'pip', 'install', '--upgrade', 'pip'], check=True)
        logger.debug("Installing executor node dependencies.")
        command = f"pip install -r {PATH_BASE_DIR}/deps/requirements.txt"
        subprocess.run(command, shell=True, executable="/bin/bash")

    def install_host_dependencies(self):
        """
        Install python dependencies on host.
        """
        status = {}

        package = ComponentInfo(component=str(PATH_BASE_DIR / "deps" / "remote_requirements.txt"), 
                                type="dependencies")

        logger.debug(f"Installing dependencies on guests: {package}")
        action_class = Action("install", package, self.ansible_data)
        status = action_class.execute()

        return status

    def update_status(self, status):
        """
        Update the status of the provision.

        Args:
            status (dict): The status of the executed action.
        """
        self.summary.update(status.stats)
