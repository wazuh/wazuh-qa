import yaml


class AnsibleTask():

    """Represent an inventory of ansible. It allows us to build inventories from a set of instances and groups.

    Args:
        items (dict): A simple task in dictionary format

    Attributes:
        items (dict): A simple task in dictionary format

    """
    def __init__(self, items):
        self.items = items

    def __str__(self):
        """Define how the class object is to be displayed."""
        task_string = yaml.dump(self.items, allow_unicode=True, sort_keys=False)

        return task_string
