import ansible_runner
import jinja2
import yaml

from pathlib import Path
from pydantic import BaseModel, IPvAnyAddress

from jinja2 import Template
from modules.generic.utils import Utils
from modules.provision.componentType import ComponentType
from modules.generic.logger import Logger

class Inventory(BaseModel):
    ansible_host: str | IPvAnyAddress
    ansible_user: str
    ansible_port: int
    ansible_ssh_private_key_file: str


class Ansible:
    def __init__(self, ansible_data, path=None):
        self.path = path
        self.playbooks_path = Path(__file__).parents[2] / 'playbooks'
        self.ansible_data = Inventory(**dict(ansible_data))
        self.inventory = self.generate_inventory()
        self.logger = Logger(__name__).get_logger()

    def render_playbooks(self, rendering_variables) -> list:
        """
        Render the playbooks with Jinja.

        Args:
            ansible_data: Data with the ansible host.
            rendering_variables: Extra variables to render the playbooks.
        """
        tasks = []
        path_to_render_playbooks = self.playbooks_path / rendering_variables.get("templates_path")
        template_loader = jinja2.FileSystemLoader(searchpath=path_to_render_playbooks)
        template_env = jinja2.Environment(loader=template_loader)

        list_template_tasks = Utils.get_template_list(
            path_to_render_playbooks, rendering_variables.get("templates_order"))

        if list_template_tasks:
            for template in list_template_tasks:
                loaded_template = template_env.get_template(template)

                rendered = yaml.safe_load(loaded_template.render(host=self.ansible_data, **rendering_variables))

                if not rendered:
                    continue

                tasks += rendered
        else:
            print("Error no templates found")

        return tasks

    def render_playbook(self, playbook: Path, rendering_variables: dict = {}) -> str | None:
        """
        Render one playbook with Jinja.

        Args:
            ansible_data: Data with the ansible host.
            rendering_variables: Extra variables to render the playbooks.
        """
        playbook = Path(playbook)
        if not playbook.exists():
            print(f"Error: Playbook {playbook} not found")
            return None
        _env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(playbook.parent))
        template = _env.get_template(playbook.name)
        rendered = template.render(
            host=self.ansible_data, **rendering_variables)

        return yaml.safe_load(rendered)

    def run_playbook(self, playbook=None, extravars=None, verbosity=1, env_vars={}):
        """
        Run the playbook with ansible_runner.

        Args:
            playbook: Playbook to run.
            extravars: Extra variables to run the playbook.
            verbosity: Verbosity level.
        """
        if self.path:
            playbook = self.path + "/" + playbook

        # Set the callback to yaml to env_vars
        env_vars['ANSIBLE_STDOUT_CALLBACK'] = 'community.general.yaml'

        result = ansible_runner.run(
            inventory=self.inventory,
            playbook=playbook,
            verbosity=verbosity,
            extravars=extravars,
            envvars=env_vars,
        )

        return result

    def generate_inventory(self) -> dict:
        """
        Generate the inventory for ansible.
        """
        inventory_data = {
            'all': {
                'hosts': {
                    self.ansible_data.ansible_host: {
                        'ansible_port': self.ansible_data.ansible_port,
                        'ansible_user': self.ansible_data.ansible_user,
                        'ansible_ssh_private_key_file': self.ansible_data.ansible_ssh_private_key_file
                    }
                }
            }
        }

        return inventory_data
