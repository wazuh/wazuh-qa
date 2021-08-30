import os
import yaml
import copy
import json
from tempfile import gettempdir
from wazuh_testing.tools.time import get_current_timestamp


class AnsibleInventory():
    """Represent an inventory of ansible. It allows us to build inventories from a set of instances and groups.

    Args:
        ansible_instances (list(AnsibleInstances)): Ansible instances that will be defined in the ansible inventory.
        inventory_file_path (str): Path were save the ansible inventory.
        ansible_groups (list(AnsibleGroups)): List of ansible groups to save in the ansible inventory.
        generate_file (boolean): True to generate the file with the inventory automatically, False otherwise.

    Attributes:
        ansible_instances (list(AnsibleInstances)): Ansible instances that will be defined in the ansible inventory.
        inventory_file_path (str): Path were save the ansible inventory.
        ansible_groups (list(AnsibleGroups)): List of ansible groups to save in the ansible inventory.

    """
    def __init__(self, ansible_instances, inventory_file_path=None, ansible_groups=None, generate_file=True):
        self.ansible_instances = ansible_instances

        self.inventory_file_path = inventory_file_path if inventory_file_path else \
            f"{gettempdir()}/{get_current_timestamp()}.yaml"
        self.ansible_groups = ansible_groups
        self.data = {}
        self.__setup_data__()
        if generate_file:
            self.write_inventory_to_file()

    def __setup_data__(self):
        """Build the ansible inventory data and save it in the data class attribute."""
        ansible_inventory_dict = {'all': {'hosts': {}, 'children': {}}}
        hosts = {}

        for instance in self.ansible_instances:
            host_info = {
                        'ansible_host': instance.host,
                        'ansible_user': instance.connection_user,
                        'ansible_password': instance.connection_user_password,
                        'ansible_connection': instance.connection_method,
                        'ansible_port': instance.connection_port,
                        'ansible_python_interpreter': instance.ansible_python_interpreter,
                        'ansible_ssh_private_key_file': instance.ssh_private_key_file_path,
                        'vars': instance.host_vars,
                        'ansible_ssh_common_args': "-o UserKnownHostsFile=/dev/null"
                        }

            # Remove ansible vars with None value
            host_info = {key: value for key, value in host_info.items() if value is not None}

            hosts[instance.host] = copy.deepcopy(host_info)

        ansible_inventory_dict['all']['hosts'] = hosts

        if self.ansible_groups:
            for group_key, group_value in self.ansible_groups.items():
                ansible_inventory_dict['all']['children'][group_key] = group_value

        self.data = ansible_inventory_dict

    def __str__(self):
        """Define how the class object is to be displayed."""
        return yaml.dump(self.data, allow_unicode=True, sort_keys=False)

    def __repr__(self):
        """Representation of the object of the class in string format"""
        return json.dumps(self.data)

    def write_inventory_to_file(self):
        """Write the ansible inventory data in a file"""
        if not os.path.exists(os.path.dirname(self.inventory_file_path)):
            os.makedirs(os.path.dirname(self.inventory_file_path))

        with open(self.inventory_file_path, 'w') as inventory:
            inventory.write(self.__str__())

    def delete_playbook_file(self):
        """Delete all created playbook files
        """
        # if os.path.exists(self.inventory_file_path):
        #     os.remove(self.inventory_file_path)
        pass
