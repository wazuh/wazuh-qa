import time # Remove in PR
import sys, os

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.append(project_root)

from src.tools import Ansible, Provision

def main():


    # General
    inventory = "inventory.yaml"
    playbook_path = "/wazuh-qa/poc-tests/playbooks/tests"

    test_playbooks = [
        "test_repo.yml",
        "test_install.yml",
        "test_registration.yml",
        "test_connection.yml",
        "test_basic_info.yml",
        "test_restart.yml",
        "test_stop.yml",
        "test_uninstall.yml"
    ]
    # Extra data
    live = True
    version = '4.6.0'
    revision = '40603'
    # Tiny bird
    tinybird_token = ''
    tinybird_datasource = 'testing_wazuh'
    tinybird_url = 'https://api.us-east.tinybird.co'

    if live:
        branch_version = "v" + version

    extra_vars = {
        'version': version,
        'revision': revision,
        'branch_version': branch_version,
        'tinybird_token': tinybird_token,
        'tinybird_datasource': tinybird_datasource,
        'tinybird_url': tinybird_url
    }


    ansible = Ansible(inventory, playbook_path)
    # provision = Provision(ansible)

    for playbook in test_playbooks:
        ansible.run_playbook(playbook, extra_vars)

if __name__ == "__main__":
    main()