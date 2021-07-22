from deployment.LocalPackage import LocalPackage
from ansible.AnsibleInventory import AnsibleInventory
from ansible.AnsibleInstance import AnsibleInstance
from deployment.WazuhSources import WazuhSources
from collections import defaultdict
from subprocess import call
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

    def parse_ifraestructure_file(self, ansible_instances, hosts, hosts_tasks, groups):

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

                        ansible_instances.append(
                            self.__read_ansible_instance(infra_obj[root_key][host_key]["host_info"]))

                        hosts_tasks[hosts[-1]] = {'wazuh_deployment': infra_obj[root_key][host_key]["wazuh_deployment"]}

                        hosts_tasks[hosts[-1]] = {'qa_framework': infra_obj[root_key][host_key]["qa_framework"]}
            elif root_key == "groups":
                groups.update({'children': infra_obj[root_key]})

    def __init__(self, infra_file_path):
        self.infra_file_path = infra_file_path


qa_provisioning = QAProvisioning("infra_def.yaml")
ansible_instances = []
hosts = []
list_tasks = {}
groups = dict()
groups_vars = {}
hosts_tasks = {}

qa_provisioning.parse_ifraestructure_file(ansible_instances=ansible_instances, hosts=hosts, groups=groups,
                                          hosts_tasks=hosts_tasks)

ansible_inventory = AnsibleInventory(ansible_instances=ansible_instances,
                                     inventory_file_path="/tmp/ansible_inventory.yaml")

wa_sources = WazuhSources("managers", "/tmp/prueba_ansible_sources/", "1596-development", "https://www.github.com/wazuh/wazuh-qa")

wa_sources.download_sources(inventory_path="ansible_inventory.yaml", playbook_path="/tmp/ansible_playbook_sources.yaml")

call(["ansible-playbook", "-i", "/tmp/ansible_inventory.yaml", "/tmp/ansible_playbook_sources.yaml"])


wa_local_package = LocalPackage("managers", "/tmp/prueba_ansible_packages/",
                                "/home/jamh/Downloads/google-chrome-stable_current_amd64.deb")
wa_local_package.download_sources(playbook_path="/tmp/ansible_playbook_packages.yaml",
                                  inventory_path="/tmp/ansible_inventory.yaml", )

call(["ansible-playbook", "-i", "/tmp/ansible_inventory.yaml", "/tmp/ansible_playbook_packages.yaml"])
