from pathlib import Path
import jinja2
from modules.generic import Ansible, Utils

class Playbooks(Ansible):

    def __init__(self, sub_path=''):
        self.playbooks_path = Path(__file__).parents()[3] / 'playbooks' / sub_path

    def render_playbooks(self, path, eextra_variables_values):
      tasks = []
      template_loader = jinja2.FileSystemLoader(searchpath=path)
      template_env = jinja2.Environment(loader=template_loader)
      list_template_tasks = Utils.get_template_list(path)

      if list_template_tasks:
        for template in list_template_tasks:
          loaded_template = template_env.get_template(template)
          rendered = yaml.safe_load(loaded_template.render(host=host_info, **eextra_variables_values))

          if not rendered:
            continue

          tasks += rendered

      return tasks

    def run_playbook(self, playbook):
       status = Ansible.run_playbook(playbook)
       return status