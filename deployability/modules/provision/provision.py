# Description: Provision module for Wazuh deployability
from modules.generic.utils import Utils
from modules.provision.models import InputPayload
from modules.provision.provisionModule import ProvisionModule
from modules.provision.install import Install, InstallComponent
from pathlib import Path
import os, subprocess, sys

PATH_BASE_DIR = Path(__file__).parents[2]

class Provision(ProvisionModule):

  def __init__(self, payload: InputPayload):
    self.ansible_data = Utils.load_from_yaml(payload.inventory, map_keys={'ansible_host': 'ansible_host',
                                                                          'ansible_user': 'ansible_user',
                                                                          'ansible_port': 'ansible_port',
                                                                          'ansible_ssh_private_key_file': 'ansible_ssh_private_key_file'})
    self.manager_ip = Utils.load_from_yaml(payload.manager_ip, map_keys={'ansible_host': 'ansible_host'}, specific_key="ansible_host")
    self.install_list = payload.install
    self.summary = {}

  # -------------------------------------
  #   Methods
  # -------------------------------------

  def run(self) -> None:
    """
    Run the provision.
    """

    #self.node_dependencies()

    self.install_host_dependencies()

    for item in self.install_list:
      print(item)
      status = self.handle_package(item)

      self.update_status(status)

    print("summary")
    print(self.summary)

  def handle_package(self, package):
    """
    Handle package to install.

    Args:
        dict -> package: Data with the package to install.
          - this: componente to install
          - with: install type
          - version: version to install (optional)
    """
    status = {}

    component = package.get("this")
    install_type = package.get("with")
    version = package.get("version")

    if "wazuh-agent" in component:
      install_type = "package"

    if not install_type:
      install_type = "generic"

    info_component_install = {
      'component': component,
      'install_type': install_type,
      'version': version
    }

    info_component_install["manager_ip"] = self.manager_ip

    install: Install = InstallComponent(self.ansible_data, info_component_install)
    status = install.install_component()

    return status

  @staticmethod
  def node_dependencies():
    """
    Install python dependencies on Worker node.
    """
    venv_path = PATH_BASE_DIR / 'venv'
    if not os.path.exists(venv_path):
        subprocess.run(['python3', '-m', 'venv', str(venv_path)], check=True)
    activate_script = os.path.join(venv_path, 'bin', 'activate')
    command = f"source {activate_script}" if sys.platform != 'win32' else f"call {activate_script}"
    subprocess.run(command, shell=True, executable="/bin/bash")
    subprocess.run(['python3', '-m', 'pip', 'install', '--upgrade', 'pip'], check=True)
    command = f"pip install -r {PATH_BASE_DIR}/deps/requirements.txt"
    subprocess.run(command, shell=True, executable="/bin/bash")

  def install_host_dependencies(self):
    """
    Install python dependencies on host.
    """
    status = {}

    package = {
      'this': os.path.join(str(PATH_BASE_DIR), "deps", "remote_requirements.txt"),
      'with': "deps"
    }

    status = self.handle_package(package)

    return status

  def update_status(self, status):
    self.summary.update(status.stats)
