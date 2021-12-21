import os
import sys
from copy import deepcopy
from tempfile import gettempdir

from wazuh_testing.tools.file import download_text_file, remove_file
from wazuh_testing.qa_ctl.provisioning.ansible import read_ansible_instance, remove_known_host
from wazuh_testing.qa_ctl.provisioning.ansible.ansible_inventory import AnsibleInventory
from wazuh_testing.qa_ctl.provisioning.ansible.ansible_runner import AnsibleRunner
from wazuh_testing.qa_ctl import QACTL_LOGGER
from wazuh_testing.tools.logging import Logging
from wazuh_testing.tools import file
from wazuh_testing.tools.time import get_current_timestamp
from wazuh_testing.qa_ctl.provisioning.local_actions import qa_ctl_docker_run


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
        self.tasks_data = tasks_data

        self.__process_tasks_data()

    def __process_tasks_data(self):
        """Process tasks module info from the qa-ctl configuration file.

        Args:
            tasks_data (dict): Dicionary with tasks info.
        """
        QATasksLauncher.LOGGER.debug('Processing tasks module data')

        for task_id, task_data in self.tasks_data.items():
            playbooks_path = []
            inventory_path = ''

            if 'host_info' in task_data:
                instance = read_ansible_instance(task_data['host_info'])

                # Remove the host IP from known host file to avoid the SSH key fingerprint error
                if 'host' in task_data['host_info']:
                    remove_known_host(task_data['host_info']['host'], QATasksLauncher.LOGGER)

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
                task_id = f"{task_data['playbooks'][index]['name']} task from playbook {playbook}" if 'name' in \
                          task_data['playbooks'][index] else f"Running playbook {playbook}"

                self.ansible_runners.append(AnsibleRunner(inventory_path, playbook,
                                                          output=self.qa_ctl_configuration.ansible_output,
                                                          task_id=task_id))

        QATasksLauncher.LOGGER.debug('Tasks module data has been processed successfully')

    def run(self):
        """Run the ansible tasks specified in the tasks module."""
        try:
            if sys.platform == 'win32':
                # If Windows, run the qa-ctl tasks in a linux container due to ansible is not compatible with Windows
                tmp_config_file_name = f"config_{get_current_timestamp()}.yaml"
                tmp_path = os.path.join(gettempdir(), 'wazuh_qa_ctl')
                tmp_config_file = os.path.join(tmp_path, tmp_config_file_name)

                # Copy the tasks data to modify
                container_tasks = deepcopy(self.tasks_data)

                # Copy the local playbooks to the wazuh qa-ctl path, that is shared with the container through a volume
                for _, task_data in container_tasks.items():
                    if 'playbooks' in task_data:
                        for playbook_data in task_data['playbooks']:
                            if 'local_path' in playbook_data:
                                file.copy(playbook_data['local_path'], tmp_path)
                                playbook_file = os.path.split(playbook_data['local_path'])[1]

                                # Update local path to specify the playbooks path in the container
                                playbook_data['local_path'] = f"/wazuh_qa_ctl/{playbook_file}"

                # Write a custom configuration file with tasks section modified (local paths)
                file.write_yaml_file(tmp_config_file, {'tasks': container_tasks})

                try:
                    qa_ctl_docker_run(tmp_config_file_name, self.qa_ctl_configuration.qa_ctl_launcher_branch,
                                      self.qa_ctl_configuration.debug_level, topic='launching the custom tasks')
                finally:
                    file.remove_file(tmp_config_file)
            else:
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
