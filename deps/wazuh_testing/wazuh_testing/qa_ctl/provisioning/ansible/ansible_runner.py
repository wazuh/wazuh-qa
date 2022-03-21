
import sys
import shutil
from tempfile import gettempdir
from os.path import join

from wazuh_testing.qa_ctl.provisioning.ansible.ansible_output import AnsibleOutput
from wazuh_testing.qa_ctl.provisioning.ansible.ansible_playbook import AnsiblePlaybook
from wazuh_testing.qa_ctl import QACTL_LOGGER
from wazuh_testing.tools.logging import Logging
from wazuh_testing.tools.exceptions import AnsibleException

if sys.platform != 'win32':
    import ansible_runner


class AnsibleRunner:
    """Allow to run ansible playbooks in the indicated hosts.

    Args:
        ansible_inventory_path (string): Path where is located the ansible inventory file.
        ansible_playbook_path (string): Path where is located the playbook file.
        private_data_dir (string): Path where the artifacts files (result files) will be stored.
        output (boolean): True for showing ansible task output in stdout False otherwise.
        task_id (str): Runner task id. It allows to identify the task.

    Attributes:
        ansible_inventory_path (string): Path where is located the ansible inventory file.
        ansible_playbook_path (string): Path where is located the playbook file.
        private_data_dir (string): Path where the artifacts files (result files) will be stored.
        output (boolean): True for showing ansible task output in stdout False otherwise.
        task_id (str): Runner task id. It allows to identify the task.
    """
    LOGGER = Logging.get_logger(QACTL_LOGGER)

    def __init__(self, ansible_inventory_path, ansible_playbook_path,
                 private_data_dir=join(gettempdir(), 'wazuh_qa_ctl'), output=False, task_id=None):
        self.ansible_inventory_path = ansible_inventory_path
        self.ansible_playbook_path = ansible_playbook_path
        self.private_data_dir = private_data_dir
        self.output = output
        self.task_id = task_id

    def run(self, log_ansible_error=True):
        """Run the ansible playbook in the indicated hosts.

        Args:
            log_ansible_error (boolean): True for logging the error exception message if any.

        Returns:
            AnsibleOutput: Result of the ansible playbook run.
        """
        quiet = not self.output
        AnsibleRunner.LOGGER.debug(f"Running {self.ansible_playbook_path} ansible-playbook with "
                                   f"{self.ansible_inventory_path} inventory")

        runner = ansible_runner.run(private_data_dir=self.private_data_dir, playbook=self.ansible_playbook_path,
                                    inventory=self.ansible_inventory_path, quiet=quiet,
                                    envvars={'ANSIBLE_GATHER_TIMEOUT': 30, 'ANSIBLE_TIMEOUT': 20})
        ansible_output = AnsibleOutput(runner)

        if ansible_output.rc != 0:
            raise AnsibleException(f'Failed: {ansible_output}', AnsibleRunner.LOGGER.error, QACTL_LOGGER) if \
                log_ansible_error else AnsibleException(f'Failed: {ansible_output}')

        return ansible_output

    @staticmethod
    def run_ephemeral_tasks(ansible_inventory_path, playbook_parameters, raise_on_error=True, output=False,
                            log_ansible_error=True):
        """Run the ansible tasks given from playbook parameters

        Args:
            ansible_inventory_path (string): Path were the ansible directory is placed.
            playbook_parameters : Parameters for the ansible playbook.
            raise_on_error (boolean): Set if errors or unexpected behaviour are goint to raise errors, Set to 'True'
                                      by default.
            output (boolean): Set if there are going to be outputs. Set to 'False' by default.
            log_ansible_error (boolean): True for logging the error exception message if any.

        Returns:
            AnsibleOutput: Result of the ansible playbook run.

        """
        ansible_playbook = AnsiblePlaybook(**playbook_parameters)
        quiet = not output

        try:
            AnsibleRunner.LOGGER.debug(f"Running {ansible_playbook.playbook_file_path} ansible-playbook with "
                                       f"{ansible_inventory_path} inventory")
            runner = ansible_runner.run(playbook=ansible_playbook.playbook_file_path, inventory=ansible_inventory_path,
                                        quiet=quiet, envvars={'ANSIBLE_GATHER_TIMEOUT': 30, 'ANSIBLE_TIMEOUT': 20})
            ansible_output = AnsibleOutput(runner)

            if ansible_output.rc != 0 and raise_on_error:
                raise AnsibleException(f'Failed: {ansible_output}', AnsibleRunner.LOGGER.error, QACTL_LOGGER) if \
                    log_ansible_error else AnsibleException(f'Failed: {ansible_output}')

            return ansible_output

        finally:
            ansible_playbook.delete_playbook_file()
            shutil.rmtree(runner.config.private_data_dir)
