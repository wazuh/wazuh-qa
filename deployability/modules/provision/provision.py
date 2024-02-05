# Description: Provision module for Wazuh deployability
from modules.generic.utils import Utils
from modules.provision.models import InputPayload
from modules.provision.provisionModule import ProvisionModule
from modules.provision.actions import Action
from pathlib import Path
import os, subprocess, sys



PATH_BASE_DIR = Path(__file__).parents[2]

class Provision(ProvisionModule):

  def __init__(self, payload: InputPayload):
    if payload.install:
      self.component_info = payload.install
      self.action = "install"
    if payload.uninstall:
      self.component_info = payload.uninstall
      self.action = "uninstall"

    self.validateManagerIp(self.component_info, payload.manager_ip)
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

    #self.node_dependencies()

    #self.install_host_dependencies()
  

    for item in self.component_info:
      action_class = Action(self.action, item, self.ansible_data)
      status = action_class.execute()

      self.update_status(status)

    print("summary")
    print(self.summary)

  def validateManagerIp(self, components, ip):
    if ip:
      for component in components:
        if component.component == 'wazuh-agent':
            component.manager_ip = ip

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
      'component': os.path.join(str(PATH_BASE_DIR), "deps", "remote_requirements.txt"),
      'action_type': "dependencies"
    }

    action_class = Action("install", package, self.ansible_data)
    status = action_class.execute()

    return status

  def update_status(self, status):
    self.summary.update(status.stats)
