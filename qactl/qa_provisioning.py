from ansible.AnsibleInventory import AnsibleInventory
from ansible.AnsibleInstance import AnsibleInstance
from collections import defaultdict
import yaml
import sys


class QAProvisioning():

    def __read_ansible_instance(self, host_info):
        return AnsibleInstance(host=host_info['host'], host_vars=host_info['host_vars'],
                               connection_method=host_info['connection_method'],
                               connection_port=host_info['connection_port'], connection_user=host_info['user'],
                               connection_user_password=host_info['password'],
                               ssh_private_key_file_path=host_info['local_private_key_file_path'],
                               ansible_python_interpreter=host_info['ansible_python_interpreter'])

    def parse_ifraestructure_file(self, ansible_instances, hosts, groups, groups_vars, hosts_tasks):

        # Open the infraestructure file definition and parse into object

        with open(self.infra_file_path) as infraestructure:
            try:
                infra_obj = yaml.safe_load(infraestructure)
            except yaml.YAMLError as yaml_e:
                print(f"Error while parsing: {yaml_e}", file=sys.stderr)

        # Parse object into AnsibleInstances

        for root_key, root_value in infra_obj.items():
            if root_key == "hosts":
                for host_key, host_value in root_value.items():
                    if "host" in host_key:
                        hosts.append(infra_obj[root_key][host_key]["host_info"]['host'])
                        current_host_group = infra_obj[root_key][host_key]["host_info"]['group']

                        if current_host_group not in groups:
                            groups.update({current_host_group: {'hosts': {}}})

                        groups[current_host_group]['hosts'].update({infra_obj[root_key][host_key]["host_info"]['host']:
                                                                    ''})

                        ansible_instances.append(
                            self.__read_ansible_instance(infra_obj[root_key][host_key]["host_info"]))

                        hosts_tasks[hosts[-1]] = {'wazuh_deployment': infra_obj[root_key][host_key]["wazuh_deployment"]}

                        hosts_tasks[hosts[-1]] = {'qa_framework': infra_obj[root_key][host_key]["qa_framework"]}
            elif root_key == "groups":
                for group_key, group_value in root_value.items():
                    groups_vars[group_key] = group_value["group_vars"]

    def __init__(self, infra_file_path):
        self.infra_file_path = infra_file_path


qa_provisioning = QAProvisioning("path_to_infraestructure_definition.yaml")
ansible_instances = []
hosts = []
list_tasks = {}
groups = defaultdict()
groups_vars = {}
hosts_tasks = {}

qa_provisioning.parse_ifraestructure_file(ansible_instances=ansible_instances, hosts=hosts, groups=groups,
                                          groups_vars=groups_vars, hosts_tasks=hosts_tasks)

ansible_inventory = AnsibleInventory(hosts=hosts, groups=groups, groups_vars=groups_vars,
                                     ansible_instances=ansible_instances,
                                     inventory_file_path="path_to_ansible_inventory.yaml")

ansible_inventory.write_inventory_to_file()
