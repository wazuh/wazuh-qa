import ansible_runner

from wazuh_testing.provisioning.ansible.AnsibleOutput import AnsibleOutput


class AnsibleRunner:
    """Allow to run ansible playbooks in the indicated hosts.

    Args:
        ansible_inventory_path (string): Path where is located the ansible inventory file.
        ansible_playbook_path (string): Path where is located the playbook file.
        private_data_dir (string): Path where the artifacts files (result files) will be stored.

    Attributes:
        ansible_inventory_path (string): Path where is located the ansible inventory file.
        ansible_playbook_path (string): Path where is located the playbook file.
        private_data_dir (string): Path where the artifacts files (result files) will be stored.
    """
    def __init__(self, ansible_inventory_path, ansible_playbook_path, private_data_dir='/tmp'):
        self.ansible_inventory_path = ansible_inventory_path
        self.ansible_playbook_path = ansible_playbook_path
        self.private_data_dir = private_data_dir

    def run(self):
        """Run the ansible playbook in the indicated hosts.

        Returns:
            AnsibleOutput: Result of the ansible playbook run.
        """
        runner = ansible_runner.run(private_data_dir=self.private_data_dir, playbook=self.ansible_playbook_path,
                                    inventory=self.ansible_inventory_path)
        ansible_output = AnsibleOutput(runner)

        return ansible_output
