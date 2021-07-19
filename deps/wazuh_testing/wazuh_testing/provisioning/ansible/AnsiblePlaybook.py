import os
import yaml


class AnsiblePlaybook():

    def __init__(self, name, tasks_list=None, playbook_file_path=None, hosts='all', gather_facts=False,
                 ignore_errors=False, become=False, playbook_vars=None):
        self.name = name
        self.hosts = hosts
        self.gather_facts = gather_facts
        self.tasks_list = tasks_list
        self.ignore_errors = ignore_errors
        self.become = become
        self.playbook_vars = playbook_vars
        self.playbook_file_path = playbook_file_path

    def __str__(self):
        playbook = {'hosts': self.hosts, 'gather_facts': self.gather_facts, 'become': self.become,
                    'ignore_errors': self.ignore_errors}

        if self.playbook_vars is not None:
            playbook['vars'] = self.playbook_vars

        if self.tasks_list is not None:
            playbook['tasks'] = []
            for ansible_task in self.tasks_list:
                playbook['tasks'].append(ansible_task.items)

        playbook_string = yaml.dump([playbook], default_flow_style=False, sort_keys=False)

        return playbook_string

    def write_playbook_to_file(self):
        if not os.path.exists(os.path.dirname(self.playbook_file_path)):
            os.makedirs(os.path.dirname(self.playbook_file_path))

        with open(self.playbook_file_path, 'w+') as file:
            file.write(self.__str__())

    def delete_playbook_file(self):
        if os.path.exists(self.playbook_file_path):
            os.remove(self.playbook_file_path)
