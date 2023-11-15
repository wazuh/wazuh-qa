from src.classes import Ansible
import time # Remove in PR

def main():

    # -------------------
    # Vars
    # -------------------

    # General
    inventory = "inventory.yaml"
    playbook_path = "/wazuh-qa/poc-tests/playbooks"

    # Provision
    playbook_provision_repo = "provision/set_repo.yml"
    playbook_provision_install = "provision/install.yml"
    playbook_provision_register = "provision/register.yml"
    playbook_provision_service = "provision/service.yml"
    playbook_provision_restart = "provision/restart.yml"

    # Test
    playbook_test_repo = "tests/test_repo.yml"
    playbook_test_provision = "tests/provision_test.yml"
    playbook_test_install = "tests/test_install.yml"
    playbook_test_registration = "tests/test_registration.yml"
    playbook_test_connection = "tests/test_connection.yml"
    playbook_test_basic_info = "tests/test_basic_info.yml"
    playbook_test_restart = "tests/restart.yml"

    # Extra data
    live = True
    version = '4.6.0'
    revision = '40603'
    if live:
        branch_version = "v" + version
    extra_vars = {
        'version': version,
        'revision': revision,
        'branch_version': branch_version,
    }

    # -------------------
    # Tasks
    # -------------------

    ansible = Ansible.Ansible(playbook_path)
    ansible.set_inventory(inventory)

    # Provision stage

    ansible.run_playbook(playbook_provision_repo)
    ansible.run_playbook(playbook_provision_install)
    ansible.run_playbook(playbook_provision_register)
    ansible.run_playbook(playbook_provision_service)

    time.sleep(20) # Agent must connect to manager. Remove in PR

    # Test stage

    # Run tests in endpoints

    ansible.run_playbook(playbook_test_provision)

    ansible.run_playbook(playbook_test_repo)
    ansible.run_playbook(playbook_test_install, extra_vars)
    ansible.run_playbook(playbook_test_registration)
    ansible.run_playbook(playbook_test_connection)
    ansible.run_playbook(playbook_test_basic_info, extra_vars)
    #ansible.run_playbook(playbook_test_service)

    time.sleep(20) # Agent must connect to manager. Remove in PR
    ansible.run_playbook(playbook_provision_restart)
    ansible.run_playbook(playbook_test_restart)

    #ansible.run_playbook(playbook_test_install, 'Agent*', extra_vars)
    #ansible.run_playbook(playbook_test_install, 'Manager*', extra_vars)

    #clear = "clear.yml"
    #ansible.run_playbook(clear)


    # -------------------


if __name__ == "__main__":
    main()