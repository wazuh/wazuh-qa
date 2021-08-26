import yaml
import os


class AnsibleRole():
    """Class to create a role from a tasks list

    Args:
        name (str): Playbook name.
        tasks (list(AnsibleTask)): List of ansible tasks that will be launched

    Attributes:
        name (str): Playbook name.
        tasks (list(AnsibleTask)): List of ansible tasks that will be launched
    """
    def __init__(self, name, tasks):
        self.name = name
        self.tasks = tasks

    def __str__(self):
        """Define how the class object is to be displayed."""
        role = [task.items for task in self.tasks]
        role_string = yaml.dump(role, allow_unicode=True, sort_keys=False)

        return role_string

    def write_to_file(self, role_file_path):
        """Write the role in a file"""
        if not os.path.exists(os.path.dirname(role_file_path)):
            os.makedirs(os.path.dirname(role_file_path))

        with open(role_file_path, 'w+') as file:
            file.write(self.__str__())

    def load_from_file(self, role_file_path):
        pass
