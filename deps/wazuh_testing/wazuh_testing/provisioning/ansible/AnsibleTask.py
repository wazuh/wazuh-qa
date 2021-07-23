import yaml


class AnsibleTask():

    def __init__(self, items):
        self.items = items

    def __str__(self):
        task_string = yaml.dump(self.items, allow_unicode=True, sort_keys=False)

        return task_string
