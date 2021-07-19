import yaml


class AnsibleTask():

    def __init__(self, name, items):
        self.name = name
        self.items = items

    def print_data(self):
        task_string = ""
        task_string += f"name: {self.name}\n"
        task_string += yaml.dump(self.items, None, allow_unicode=True)

        return task_string


"""
item_dict = {"become": "true", "service": {"name": "wazuh-agent", "state": "restarted"}, "when": "os == 'macos' or os == 'solaris-11' or os == 'solaris-10'"}
my_task = AnsibleTask("task_name", item_dict)
task_string = my_task.print_data()

print(task_string)
"""
