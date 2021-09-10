import subprocess

from wazuh_testing.tools import file
from wazuh_testing.qa_ctl.provisioning.ansible.ansible_inventory import AnsibleInventory
from wazuh_testing.qa_ctl.provisioning.ansible.ansible_instance import AnsibleInstance
from wazuh_testing.qa_ctl.provisioning.qa_framework.qa_framework import QAFramework


LOCALHOST = '127.0.0.1'
LOCAL_ANSIBLE_INSTANCE = [AnsibleInstance('127.0.0.1', 'local_user', connection_method='local')]


def download_local_wazuh_qa_repository(branch, path):
    qa_instance = QAFramework(ansible_output=False, qa_branch=branch, workdir=path)

    inventory = AnsibleInventory(LOCAL_ANSIBLE_INSTANCE)
    try:
        qa_instance.download_qa_repository(inventory_file_path=inventory.inventory_file_path, hosts=LOCALHOST)
    finally:
        file.delete_file(inventory.inventory_file_path)


def run_local_command(command):
    run = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)

    return run.stdout.read().decode()
