from tempfile import gettempdir

from wazuh_testing.provisioning.ansible.AnsibleTask import AnsibleTask
from wazuh_testing.provisioning.ansible.AnsibleRunner import AnsibleRunner


class QAFramework():
    """Encapsulates all the functionality regarding the preparation and installation of qa-framework

    Args:
        workdir (str): Directory where the qa repository files are stored
        qa_repository (str): Url to the QA repository.
        qa_branch (str): QA branch of the qa repository.

    Attributes:
        workdir (str): Directory where the qa repository files are stored
        qa_repository (str): Url to the QA repository.
        qa_branch (str): QA branch of the qa repository.
    """

    def __init__(self, workdir=gettempdir(), qa_repository='https://github.com/wazuh/wazuh-qa.git', qa_branch='master'):
        self.qa_repository = qa_repository
        self.qa_branch = qa_branch
        self.workdir = f"{workdir}/wazuh_qa"

    def install_dependencies(self, inventory_file_path, hosts='all'):
        """Install all the necessary dependencies to allow the execution of the tests.

        Args:
            inventory_file_path (str): Path were save the ansible inventory.
        """
        dependencies_task = AnsibleTask({'name': 'Install python dependencies',
                                         'shell': 'pip3 install -r requirements.txt --no-cache-dir --upgrade '\
                                                  '--only-binary=:cryptography,grpcio:',
                                         'args': {'chdir': self.workdir}})
        ansible_tasks = [dependencies_task]
        playbook_parameters = {'hosts': hosts, 'tasks_list': ansible_tasks}
        AnsibleRunner.run_ephemeral_tasks(inventory_file_path, playbook_parameters)

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

        AnsibleRunner.run_ephemeral_tasks(inventory_file_path, playbook_parameters)

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

        AnsibleRunner.run_ephemeral_tasks(inventory_file_path, playbook_parameters)
