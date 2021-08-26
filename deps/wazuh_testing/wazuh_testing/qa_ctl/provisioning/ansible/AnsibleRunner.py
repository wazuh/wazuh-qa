import ansible_runner

from tempfile import gettempdir

from wazuh_testing.qa_ctl.provisioning.ansible.AnsibleOutput import AnsibleOutput
from wazuh_testing.qa_ctl.provisioning.ansible.AnsiblePlaybook import AnsiblePlaybook
from wazuh_testing.qa_ctl import QACTL_LOGGER
from wazuh_testing.tools.logging import Logging


class AnsibleRunner:
    """Allow to run ansible playbooks in the indicated hosts.

    Args:
        ansible_inventory_path (string): Path where is located the ansible inventory file.
        ansible_playbook_path (string): Path where is located the playbook file.
        private_data_dir (string): Path where the artifacts files (result files) will be stored.
        output (boolean): True for showing ansible task output in stdout False otherwise.

    Attributes:
        ansible_inventory_path (string): Path where is located the ansible inventory file.
        ansible_playbook_path (string): Path where is located the playbook file.
        private_data_dir (string): Path where the artifacts files (result files) will be stored.
        output (boolean): True for showing ansible task output in stdout False otherwise.
    """
    LOGGER = Logging.get_logger(QACTL_LOGGER)

    def __init__(self, ansible_inventory_path, ansible_playbook_path, private_data_dir=gettempdir(), output=False):
        self.ansible_inventory_path = ansible_inventory_path
        self.ansible_playbook_path = ansible_playbook_path
        self.private_data_dir = private_data_dir
        self.output = output

    def run(self):
        """Run the ansible playbook in the indicated hosts.

        Returns:
            AnsibleOutput: Result of the ansible playbook run.
        """
        quiet = not self.output
        AnsibleRunner.LOGGER.debug(f"Running {self.ansible_playbook_path} ansible-playbook with "
                                   f"{self.ansible_inventory_path} inventory")
        runner = ansible_runner.run(private_data_dir=self.private_data_dir, playbook=self.ansible_playbook_path,
                                    inventory=self.ansible_inventory_path, quiet=quiet)
        ansible_output = AnsibleOutput(runner)

        if ansible_output.rc != 0:
            raise Exception(f"The playbook execution has failed. RC = {ansible_output.rc}")

        return ansible_output

    @staticmethod
    def run_ephemeral_tasks(ansible_inventory_path, playbook_parameters, raise_on_error=True, output=False):
        ansible_playbook = AnsiblePlaybook(**playbook_parameters)
        quiet = not output

        try:
            runner = ansible_runner.run(playbook=ansible_playbook.playbook_file_path, inventory=ansible_inventory_path,
                                        quiet=quiet)
            ansible_output = AnsibleOutput(runner)

            if ansible_output.rc != 0 and raise_on_error:
                raise Exception(f'Failed: {ansible_output}')

            return ansible_output

        finally:
            ansible_playbook.delete_playbook_file()
