import src.classes.Ansible as Ansible

def main():

    inventory = "inventory.yaml"
    playbook_path = "/home/nonsatus/Documents/Wazuh/Repositories/wazuh-qa/4524/playbooks"
    playbook_provision = "provision/provision_test.yml"
    playbook_install = "provision/install.yml"
    playbook_test = "tests/test_install.yml"

    ansible = Ansible.Ansible(playbook_path)
    ansible.set_inventory(inventory)
    #ansible.run_playbook(playbook_install)
    #ansible.run_playbook(playbook_provision)
    #ansible.run_playbook(playbook_test, "Agent*")


if __name__ == "__main__":
    main()