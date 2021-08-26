import ansible_runner

from tempfile import gettempdir

from wazuh_testing.qa_ctl.provisioning.ansible.ansible_output import AnsibleOutput
from wazuh_testing.qa_ctl.provisioning.ansible.ansible_playbook import AnsiblePlaybook


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
    def __init__(self, ansible_inventory_path, ansible_playbook_path, private_data_dir=gettempdir()):
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

        if ansible_output.rc != 0:
            raise Exception(f"The playbook execution has failed. RC = {ansible_output.rc}")

        return ansible_output

    @staticmethod
    def run_ephemeral_tasks(ansible_inventory_path, playbook_parameters, raise_on_error=True):
        ansible_playbook = AnsiblePlaybook(**playbook_parameters)

        try:
            runner = ansible_runner.run(playbook=ansible_playbook.playbook_file_path, inventory=ansible_inventory_path)
            ansible_output = AnsibleOutput(runner)

            if ansible_output.rc != 0 and raise_on_error:
                raise Exception(f'Failed: {ansible_output}')

            return ansible_output

        finally:
            ansible_playbook.delete_playbook_file()
