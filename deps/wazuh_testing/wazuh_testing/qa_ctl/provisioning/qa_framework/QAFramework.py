from tempfile import gettempdir

from wazuh_testing.qa_ctl.provisioning.ansible.AnsibleTask import AnsibleTask
from wazuh_testing.qa_ctl.provisioning.ansible.AnsibleRunner import AnsibleRunner
from wazuh_testing.qa_ctl import QACTL_LOGGER
from wazuh_testing.tools.logging import Logging

class QAFramework():
    """Encapsulates all the functionality regarding the preparation and installation of qa-framework

    Args:
        workdir (str): Directory where the qa repository files are stored
        qa_repository (str): Url to the QA repository.
        qa_branch (str): QA branch of the qa repository.
        qa_ctl_configuration (QACTLConfiguration): QACTL configuration.

    Attributes:
        workdir (str): Directory where the qa repository files are stored
        qa_repository (str): Url to the QA repository.
        qa_branch (str): QA branch of the qa repository.
        qa_ctl_configuration (QACTLConfiguration): QACTL configuration.
    """
    LOGGER = Logging.get_logger(QACTL_LOGGER)

    def __init__(self, qa_ctl_configuration, workdir=gettempdir(), qa_branch='master',
                 qa_repository='https://github.com/wazuh/wazuh-qa.git'):
        self.qa_repository = qa_repository
        self.qa_branch = qa_branch
        self.workdir = f"{workdir}/wazuh-qa"
        self.qa_ctl_configuration = qa_ctl_configuration

    def install_dependencies(self, inventory_file_path, hosts='all'):
        """Install all the necessary dependencies to allow the execution of the tests.

        Args:
            inventory_file_path (str): Path were save the ansible inventory.
        """
        dependencies_task = AnsibleTask({'name': 'Install python dependencies',
                                         'shell': 'python3 -m pip install -r requirements.txt --no-cache-dir --upgrade '
                                                  '--only-binary=:cryptography,grpcio: --ignore-installed',
                                         'args': {'chdir': self.workdir}})
        ansible_tasks = [dependencies_task]
        playbook_parameters = {'hosts': hosts, 'tasks_list': ansible_tasks}
        QAFramework.LOGGER.debug(f"Installing python dependencies in {hosts} hosts.")

        AnsibleRunner.run_ephemeral_tasks(inventory_file_path, playbook_parameters,
                                          output=self.qa_ctl_configuration.ansible_output)

    def install_framework(self, inventory_file_path, hosts='all'):
        """Install the wazuh_testing framework to allow the execution of the tests.

        Args:
            inventory_file_path (str): Path were save the ansible inventory.
        """
        install_framework_task = AnsibleTask({'name': 'Install wazuh-qa framework',
                                              'shell': 'python3 setup.py install',
                                              'args': {'chdir': f"{self.workdir}/deps/wazuh_testing"}})
        ansible_tasks = [install_framework_task]
        playbook_parameters = {'hosts': hosts, 'tasks_list': ansible_tasks, 'become': True}
        QAFramework.LOGGER.debug(f"Installing wazuh-qa framework in {hosts} hosts.")

        AnsibleRunner.run_ephemeral_tasks(inventory_file_path, playbook_parameters,
                                          output=self.qa_ctl_configuration.ansible_output)

    def download_qa_repository(self, inventory_file_path, hosts='all'):
        """Download the qa-framework in the specified attribute workdir.

        Args:
            inventory_file_path (str): Path were save the ansible inventory.
        """
        create_path_task = AnsibleTask({'name': f"Create {self.workdir} path",
                                        'file': {'path': self.workdir, 'state': 'directory', 'mode': '0755'}})

        download_qa_repo_task = AnsibleTask({'name': f"Download {self.qa_repository} QA repository",
                                             'git': {'repo': self.qa_repository, 'dest': self.workdir,
                                                     'version': self.qa_branch}})
        ansible_tasks = [create_path_task, download_qa_repo_task]
        playbook_parameters = {'hosts': hosts, 'tasks_list': ansible_tasks}
        QAFramework.LOGGER.debug(f"Downloading qa-repository in {hosts} hosts")

        AnsibleRunner.run_ephemeral_tasks(inventory_file_path, playbook_parameters,
                                          output=self.qa_ctl_configuration.ansible_output)
