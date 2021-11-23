import os
from tempfile import gettempdir

from wazuh_testing.tools.file import download_text_file, remove_file
from wazuh_testing.qa_ctl.provisioning.ansible.unix_ansible_instance import UnixAnsibleInstance
from wazuh_testing.qa_ctl.provisioning.ansible.windows_ansible_instance import WindowsAnsibleInstance
from wazuh_testing.qa_ctl.provisioning.ansible.ansible_inventory import AnsibleInventory
from wazuh_testing.qa_ctl.provisioning.ansible.ansible_runner import AnsibleRunner
from wazuh_testing.qa_ctl import QACTL_LOGGER
from wazuh_testing.tools.logging import Logging
from wazuh_testing.tools.time import get_current_timestamp


class QATasksLauncher:
    """Class to manage and launch the tasks specified in the qa-ctl configuration module.

    Args:
        tasks_data (dict): Dicionary with tasks info.
        qa_ctl_configuration (QACTLConfiguration): QACTL configuration info.

    Attributes:
        tasks_data (dict): Dicionary with tasks info.
        qa_ctl_configuration (QACTLConfiguration): QACTL configuration info.
    """
    LOGGER = Logging.get_logger(QACTL_LOGGER)

    def __init__(self, tasks_data, qa_ctl_configuration):
        self.qa_ctl_configuration = qa_ctl_configuration
        self.ansible_runners = []

        self.__process_tasks_data(tasks_data)

    def __read_ansible_instance(self, host_info):
        """Read every host info and generate the AnsibleInstance object.

        Args:
            host_info (dict): Dict with the host info needed coming from config file.

        Returns:
            instance (AnsibleInstance): Contains the AnsibleInstance for a given host.
        """
        extra_vars = None if 'host_vars' not in host_info else host_info['host_vars']
        private_key_path = None if 'local_private_key_file_path' not in host_info \
            else host_info['local_private_key_file_path']

        if host_info['system'] == 'windows':
            instance = WindowsAnsibleInstance(
                host=host_info['host'],
                ansible_connection=host_info['ansible_connection'],
                ansible_port=host_info['ansible_port'],
                ansible_user=host_info['ansible_user'],
                ansible_password=host_info['ansible_password'],
                ansible_python_interpreter=host_info['ansible_python_interpreter'],
                host_vars=extra_vars
            )
        else:
            instance = UnixAnsibleInstance(
                host=host_info['host'],
                ansible_connection=host_info['ansible_connection'],
                ansible_port=host_info['ansible_port'],
                ansible_user=host_info['ansible_user'],
                ansible_password=host_info['ansible_password'],
                host_vars=extra_vars,
                ansible_ssh_private_key_file=private_key_path,
                ansible_python_interpreter=host_info['ansible_python_interpreter']
            )

        return instance

    def __process_tasks_data(self, tasks_data):
        """Process tasks module info from the qa-ctl configuration file.

        Args:
            tasks_data (dict): Dicionary with tasks info.
        """
        QATasksLauncher.LOGGER.debug('Processing tasks module data')

        for task_id, task_data in tasks_data.items():
            playbooks_path = []
            inventory_path = ''

            if 'host_info' in task_data:
                instance = self.__read_ansible_instance(task_data['host_info'])
                inventory_instance = AnsibleInventory(ansible_instances=[instance])
                inventory_path = inventory_instance.inventory_file_path

            if 'playbooks' in task_data:
                for playbook_data in task_data['playbooks']:
                    if 'local_path' in playbook_data:
                        playbooks_path.append(playbook_data['local_path'])
                    elif 'remote_url' in playbook_data:
                        # If a remote url file is specified, then download it and then save the playbook path
                        playbook_name = os.path.split(playbook_data['remote_url'])[1]
                        playbook_file_name = f"{get_current_timestamp()}_{playbook_name}"
                        playbook_file_path = os.path.join(gettempdir(), 'wazuh_qa_ctl', playbook_file_name)

                        download_text_file(playbook_data['remote_url'], playbook_file_path)
                        playbooks_path.append(playbook_file_path)

                        QATasksLauncher.LOGGER.debug(f"The {playbook_name} file has been downloaded from "
                                                     f"{playbook_data['remote_url']} in {playbook_file_path} path")

            # Create runner objects. One for each playbook using the same inventory for each host
            for index, playbook in enumerate(playbooks_path):
                self.ansible_runners.append(AnsibleRunner(inventory_path, playbook,
                                                          output=self.qa_ctl_configuration.ansible_output,
                                                          task_id=f"{task_id} - playbook_{index + 1}"))

        QATasksLauncher.LOGGER.debug('Tasks module data has been processed successfully')

    def run(self):
        """Run the ansible tasks specified in the tasks module."""
        try:
            for task_runner in self.ansible_runners:
                QATasksLauncher.LOGGER.info(f"Running {task_runner.task_id}")
                task_runner.run()
                QATasksLauncher.LOGGER.info(f"The {task_runner.task_id} has been finished successfully")
        finally:
            self.destroy()

    def destroy(self):
        """Remove temporarily runner files."""
        for runner in self.ansible_runners:
            remove_file(runner.ansible_inventory_path)
