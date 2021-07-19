import yaml
import os


class AnsibleRole():

    def __init__(self, name, tasks):
        self.name = name
        self.tasks = tasks

    def __str__(self):
        role = [task.items for task in self.tasks]
        role_string = yaml.dump(role, allow_unicode=True, sort_keys=False)

        return role_string

    def write_to_file(self, role_file_path):
        if not os.path.exists(os.path.dirname(role_file_path)):
            os.makedirs(os.path.dirname(role_file_path))

        with open(role_file_path, 'w+') as file:
            file.write(self.__str__())

    def load_from_file(self, role_file_path):
        pass
