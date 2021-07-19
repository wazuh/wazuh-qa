import textwrap


class AnsibleRole():

    def __init__(self, tasks):
        # self.name = name
        # self.role_file_path = role_file_path
        self.tasks = tasks

    def generate_role(self):
        role_string = "tasks:\n"
        for task in self.tasks:
            task_string = task.print_data()
            indent_task = textwrap.indent(task_string, '  ')
            role_string += indent_task.replace(' ', '-', 1)
            role_string += '\n'
        return role_string

    def write_role_to_file(self, role):
        with open(self.role_file_path, 'w+') as file:
            file.write(role)


"""
task1 = {"become": "true", "service": {"name": "wazuh-agent", "state": "restarted"}, "when": "os == 'macos' or os == 'solaris-11' or os == 'solaris-10'"}
my_task1 = AnsibleTask("task_name1", task1)

task2 = {"asdf": "true", "service": {"name": "wazuh-agent", "state": "restarted"}, "when": "os == 'macos' or os == 'solaris-11' or os == 'solaris-10'"}
my_task2 = AnsibleTask("task_name2", task2)

task3 = {"fdsa": "true", "service": {"name": "wazuh-agent", "state": "restarted"}, "when": "os == 'macos' or os == 'solaris-11' or os == 'solaris-10'"}
my_task3 = AnsibleTask("task_name3", task3)

tasks_list = [my_task1, my_task2, my_task3]
my_role = AnsibleRole("role_name", "/home/vhalgarv/drawers/rol.yaml", tasks_list)
role_string = my_role.generate_role()
"""
