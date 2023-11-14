import yaml
import ansible_runner


class Ansible:

    # -------------------------------------
    #   Variables
    # -------------------------------------

    inventory = None
    path = ""

    # -------------------------------------
    #   Constructor
    # -------------------------------------

    #def __init__(self, playbook_path,inventory):
    #    self.path = playbook_path
    #    self.inventory = self.set_inventory(inventory)

    def __init__(self,inventory):
        self.inventory = self.set_inventory(inventory)

    # -------------------------------------
    #   Setters and Getters
    # -------------------------------------

    def set_inventory(self, inventory):
        with open(inventory, 'r') as file:
            inv = yaml.safe_load(file)
        return inv

    def set_path(self, path):
        self.path = path

    def get_inventory(self):
        return self.inventory

    # -------------------------------------
    #   Methods
    # -------------------------------------

    # https://ansible.readthedocs.io/projects/runner/en/1.1.0/ansible_runner.html
    def run_playbook(self, playbook=None, extravars=None, verbosity=1):
        result = ansible_runner.run(
            inventory=self.inventory,
            playbook=playbook,
            verbosity=verbosity,
            extravars=extravars
        )
        return result

