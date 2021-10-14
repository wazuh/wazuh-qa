import yaml
import json


class AnsibleGroup():
    """Allow to define host groups for ansible. These host groups will be used to define the AnsibleInventory

    Args:
        name (str): Group name.
        ansible_instances (list(AnsibleInstance)): List of ansible instances that will be grouped.
        group_vars (dict): Set of variables that will belong to the group.

    Attributes:
        name (str): Group name.
        ansible_instances (list(AnsibleInstance)): List of ansible instances that will be grouped.
        group_vars (dict): Set of variables that will belong to the group.
        data (dict): Ansible group data represented in a dictionary
    """
    def __init__(self, name, ansible_instances, group_vars=None):
        self.name = name
        self.ansible_instances = ansible_instances
        self.group_vars = group_vars
        self.data = {}
        self.__setup_data__()

    def __setup_data__(self):
        """Build the group data and save it in the data class attribute."""
        data = {self.name: {'hosts': {}}}

        for ansible_instance in self.ansible_instances:
            data[self.name]['hosts'][ansible_instance.host] = {}

            if ansible_instance.host_vars:
                data[self.name]['hosts'][ansible_instance.host] = ansible_instance.host_vars

        if self.group_vars:
            data[self.name]['vars'] = self.group_vars

        self.data = data

    def __str__(self):
        """Define how the class object is to be displayed."""
        return yaml.dump(self.data, allow_unicode=True, sort_keys=False)

    def __repr__(self):
        """Representation of the object of the class in string format"""
        return json.dumps(self.data)
