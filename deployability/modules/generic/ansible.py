import yaml
import ansible_runner
import jinja2

from pathlib import Path

from modules.generic.utils import Utils


from pydantic import BaseModel, IPvAnyAddress


class Inventory(BaseModel):
    ansible_host: str | IPvAnyAddress
    ansible_user: str
    ansible_port: int
    ansible_ssh_private_key_file: str


class Ansible:

    def __init__(self, ansible_data: Inventory, path: str | Path = None):
        self.path = path

        self.playbooks_path = Path(__file__).parents[2] / 'playbooks'
        self.ansible_data = Inventory(**dict(ansible_data))
        self.inventory = {'all': {'hosts': {'dtt1': dict(self.ansible_data)}}}

        self.ansible_host = self.ansible_data.ansible_host
        self.ansible_port = self.ansible_data.ansible_port
        self.ansible_user = self.ansible_data.ansible_user
        self.ansible_user = self.ansible_data.ansible_ssh_private_key_file

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

        list_template_tasks = Utils.get_template_list(path_to_render_playbooks)

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

    def render_playbook(self, playbook: Path, rendering_variables: dict = {}) -> str | None:
        """
        Render the playbook with Jinja.

        Args:
            ansible_data: Data with the ansible host.
            rendering_variables: Extra variables to render the playbooks.
        """
        playbook = Path(playbook)
        if not playbook.exists():
            print(f"Error: Playbook {playbook} not found")
            return None
        _env = jinja2.Environment(loader=jinja2.FileSystemLoader(playbook.parent))
        template = _env.get_template(playbook.name)
        rendered = template.render(host=self.ansible_data, **rendering_variables)

        return yaml.safe_load(rendered)

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
            extravars=extravars,
            envvars={'ANSIBLE_STDOUT_CALLBACK': 'community.general.yaml'},
        )

        return result
