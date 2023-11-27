import jinja2
import yaml
import os

class Provision:

    # -------------------------------------
    #   Variables
    # -------------------------------------

    LIST_TASKS = ["set_repo.j2", "install.j2", "register.j2", "service.j2"]
    LIST_AIO_TASKS = ["download.j2", "install.j2"]
    GENERIC_TASKS = ["install.j2"]

    # -------------------------------------
    #   Constructor
    # -------------------------------------

    def __init__(self, ansible):
        self.ansible = ansible

    # -------------------------------------
    #   Setters and Getters
    # -------------------------------------

    def set_directory(self, directory):
      self.current_dir = directory

    def get_inventory(self):
        return self.ansible.inventory

    # -------------------------------------
    #   Methods
    # -------------------------------------

    def handle_package(self, host, host_info, install_info):
      status = {}

      if install_info.get('install_type') is None:
        print("Installing external package")
        install_info['install_type'] = "external"
        status = self.install(host, host_info, install_info, self.GENERIC_TASKS)
      elif "package" in install_info.get('install_type') or "wazuh-agent" in install_info.get('component'):
        print("Installing Wazuh package with package manager")
        install_info['install_type'] = "wazuh/" + install_info.get('install_type')
        status = self.install(host, host_info, install_info, self.LIST_TASKS)
      elif "aio" in install_info.get('install_type'):
        print("Installing Wazuh package with AIO")
        install_info['install_type'] = "wazuh/" + install_info.get('install_type')
        status = self.install(host, host_info, install_info, self.LIST_AIO_TASKS)

      return status

    # -------------------------------------

    def install(self, host, host_info, install_info, list_tasks):
      status = {}
      tasks = []

      playbook_path = os.path.join(self.current_dir, "playbooks", "provision", install_info.get('install_type'))
      template_loader = jinja2.FileSystemLoader(searchpath=playbook_path)
      template_env = jinja2.Environment(loader=template_loader)
      variables_values = self.set_extra_variables(host_info, install_info)

      for template in list_tasks:
        loaded_template = template_env.get_template(template)
        rendered = yaml.safe_load(loaded_template.render(host=host_info, **variables_values))

        if not rendered:
          continue

        tasks += rendered

      playbook = {
        'hosts': host,
        'become': True,
        'tasks': tasks
      }

      status = self.ansible.run_playbook(playbook)

      return status

    # -------------------------------------

    def set_extra_variables(self, host_info, install_info):
      variables_values = {}
      variables_values.update({"component": install_info.get('component')})

      if "package" in install_info.get('install_type'):
        if "wazuh-agent" in install_info.get('component') and host_info.get('manager_ip'):
          variables_values.update({
            "manager_ip": host_info.get('manager_ip')})

        if "wazuh-server" in install_info.get('component'):
          pass # For future configurations

      # Fix name variable with iterator
      if "aio" in install_info.get('install_type'):
        variables_values.update({
          "version": install_info.get('version'),
          "name": install_info.get('component'),
          "component": install_info.get('component')})

      return variables_values

    # -------------------------------------
