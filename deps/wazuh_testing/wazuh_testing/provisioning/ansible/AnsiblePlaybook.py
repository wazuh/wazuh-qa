import os
import textwrap
import yaml
from AnsibleRole import AnsibleRole
from AnsibleTask import AnsibleTask


class AnsiblePlaybook():

    def __init__(self, name, hosts, gather_facts, tasks_list, ignore_errors, become, list_vars, playbook_file_path):
        self.name = name
        self.hosts = hosts
        self.gather_facts = gather_facts
        self.tasks_list = tasks_list
        self.ignore_errors = ignore_errors
        self.become = become
        self.list_vars = list_vars
        self.playbook_file_path = playbook_file_path

    def generate_playbook(self):
        playbook_string = ""
        host_string = f"hosts: {self.hosts}\n"
        host_string += f"gather_facts: {self.gather_facts}\n"
        host_string += f"become: {self.become}\n"
        if self.list_vars:
            host_string += "vars:\n"
            host_var_string = yaml.dump(self.list_vars, None, allow_unicode=True)
            host_string += f"{textwrap.indent(host_var_string, '  ')}"

        playbook_string += f"{textwrap.indent(host_string, '  ')}".replace(' ', '-', 1)

        if self.tasks_list:
            my_role = AnsibleRole(self.tasks_list)
            role_string = my_role.generate_role()
            playbook_string += f"{textwrap.indent(role_string, '  ')}"

        return playbook_string

    def write_playbook_to_file(self, playbook):
        with open(self.playbook_file_path, 'w+') as file:
            file.write(playbook)

    def delete_playbook_file(self):
        if os.path.exists(self.playbook_file_path):
            os.remove(self.playbook_file_path)


task1 = {"become": "true", "service": {"name": "wazuh-agent", "state": "restarted"}, "when": "os == 'macos' or os == 'solaris-11' or os == 'solaris-10'"}
my_task1 = AnsibleTask("task_name1", task1)

task2 = {"asdf": "true", "service": {"name": "wazuh-agent", "state": "restarted"}, "when": "os == 'macos' or os == 'solaris-11' or os == 'solaris-10'"}
my_task2 = AnsibleTask("task_name2", task2)

task3 = {"fdsa": "true", "service": {"name": "wazuh-agent", "state": "restarted"}, "when": "os == 'macos' or os == 'solaris-11' or os == 'solaris-10'"}
my_task3 = AnsibleTask("task_name3", task3)

vars = {"var1": "value1", "var2": "value2"}

tasks_list = [my_task1, my_task2, my_task3]

my_playbook = AnsiblePlaybook("playbook_test", "group_test", "yes", tasks_list, None, "true", vars, "/home/vhalgarv/drawers/git/wazuh-qa/deps/wazuh_testing/qactl/qa_provisioning/playbook.yaml")
playbook_string = my_playbook.generate_playbook()
my_playbook.write_playbook_to_file(playbook_string)
