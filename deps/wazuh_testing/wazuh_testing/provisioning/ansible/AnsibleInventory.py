import sys
import yaml
from collections import defaultdict
from yaml.error import YAMLError


class AnsibleInventory():

    def __generate_inventory(self):

        ansible_inventory_dict = {'all': {'hosts': {}, 'children': {}}}

        hosts = {}

        for instance in self.ansible_instances:
            host_info = {
                        "ansible_host": instance.host,
                        "ansible_connection": instance.connection_method,
                        "ansible_port": instance.connection_port,
                        "ansible_user": instance.connection_user,
                        "ansible_password": instance.connection_user_password,
                        "ansible_python_interpreter": instance.ansible_python_interpreter
                        }
            if instance.host_vars:
                host_info.update({'vars': instance.host_vars})
            if instance.connection_method == "ssh":
                host_info.update({'ansible_ssh_private_key_file': instance.ssh_private_key_file_path})

            hosts.update({instance.host: host_info})

        ansible_inventory_dict["all"]['hosts'] = hosts

        ansible_inventory_dict['all']['children'] = self.groups['children']

        ansible_inventory_stream = yaml.dump(ansible_inventory_dict)

        return ansible_inventory_stream

    def write_inventory_to_file(self):
        with open(self.inventory_file_path, "w") as inventory:
            ansible_inventory_stream = self.__generate_inventory()
            inventory.writelines(ansible_inventory_stream)

    def print_data(self):
        pass

    def __init__(self, ansible_instances, inventory_file_path, hosts={}, groups={}, groups_vars={}):
        self.inventory_file_path = inventory_file_path
        self.ansible_instances = ansible_instances
        self.hosts = hosts
        self.groups = groups
        self.ansible_instances = ansible_instances
