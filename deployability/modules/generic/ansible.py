import yaml
import ansible_runner
from pathlib import Path
import jinja2
from jinja2 import Template
from modules.generic.utils import Utils
import subprocess, json

class Ansible:

  def __init__(self, ansible_data, path=None):
    self.path = path
    self.playbooks_path = Path(__file__).parents[2] / 'playbooks'
    self.ansible_data = ansible_data
    self.ansible_host = self.ansible_data.get('ansible_host')
    self.ansible_port = self.ansible_data.get('ansible_port')
    self.ansible_user = self.ansible_data.get('ansible_user')
    self.ansible_ssh_private_key_file = self.ansible_data.get('ansible_ssh_private_key_file')
    self.inventory = self.generate_inventory()

  def render_playbooks(self, variables_rendering):
    """
    Render the playbooks with Jinja.

    Args:
        ansible_data: Data with the ansible host.
        variables_rendering: Extra variables to render the playbooks.
    """
    tasks = []
    path_to_render_playbooks = self.playbooks_path / variables_rendering['templates_path']
    template_loader = jinja2.FileSystemLoader(searchpath=path_to_render_playbooks)
    template_env = jinja2.Environment(loader=template_loader)

    list_template_tasks = Utils.get_template_list(path_to_render_playbooks, variables_rendering.get('list_template_order'))

    if list_template_tasks:
      for template in list_template_tasks:
        loaded_template = template_env.get_template(template)
        rendered = yaml.safe_load(loaded_template.render(host=self.ansible_data, **variables_rendering))

        if not rendered:
          continue

        tasks += rendered
    else:
      print("Error no templates found")

    return tasks

  def run_playbook(self, playbook=None, extravars=None, verbosity=1):
    """
    Run the playbook with ansible_runner.

    Args:
        playbook: Playbook to run.
        extravars: Extra variables to run the playbook.
        verbosity: Verbosity level.
    """
    if self.path:
      playbook = self.path + "/" + playbook

    result = ansible_runner.run(
        inventory=self.inventory,
        playbook=playbook,
        verbosity=verbosity,
        extravars=extravars
    )

    return result

  def generate_inventory(self):
    """
    Generate the inventory for ansible.
    """
    inventory_data = {
        'all': {
            'hosts': {
                self.ansible_host: {
                    'ansible_port': self.ansible_port,
                    'ansible_user': self.ansible_user,
                    'ansible_ssh_private_key_file': self.ansible_ssh_private_key_file
                }
            }
        }
    }

    return inventory_data
