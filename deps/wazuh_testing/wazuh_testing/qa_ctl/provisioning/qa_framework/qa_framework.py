from os.path import join
from tempfile import gettempdir

from wazuh_testing.qa_ctl.provisioning.ansible.ansible_task import AnsibleTask
from wazuh_testing.qa_ctl.provisioning.ansible.ansible_runner import AnsibleRunner
from wazuh_testing.qa_ctl import QACTL_LOGGER
from wazuh_testing.tools.logging import Logging
from wazuh_testing.tools.file import join_path


class QAFramework():
    """Encapsulates all the functionality regarding the preparation and installation of qa-framework

    Args:
        workdir (str): Directory where the qa repository files are stored
        qa_repository (str): Url to the QA repository.
        qa_branch (str): QA branch of the qa repository.
        ansible_output (boolean): True if show ansible tasks output False otherwise.
        ansible_admin_user (str): User to launch the ansible task with admin privileges (ansible_become_user)

    Attributes:
        workdir (str): Directory where the qa repository files are stored
        qa_repository (str): Url to the QA repository.
        qa_branch (str): QA branch of the qa repository.
        ansible_output (boolean): True if show ansible tasks output False otherwise.
        ansible_admin_user (str): User to launch the ansible task with admin privileges (ansible_become_user)
    """
    LOGGER = Logging.get_logger(QACTL_LOGGER)

    def __init__(self, ansible_output=False, workdir=join(gettempdir(), 'wazuh_qa_ctl'), qa_branch='master',
                 qa_repository='https://github.com/wazuh/wazuh-qa.git', ansible_admin_user='vagrant'):
        self.qa_repository = qa_repository
        self.qa_branch = qa_branch
        self.workdir = workdir
        self.ansible_output = ansible_output
        self.system_path = 'windows' if '\\' in self.workdir else 'unix'
        self.ansible_admin_user = ansible_admin_user

    def install_dependencies(self, inventory_file_path, hosts='all'):
        """Install all the necessary dependencies to allow the execution of the tests.

        Args:
            inventory_file_path (str): Path were save the ansible inventory.
        """
        dependencies_unix_task = AnsibleTask({
            'name': 'Install python dependencies (Unix)',
            'shell': 'python3 -m pip install -r requirements.txt',
            'args': {'chdir': join_path([self.workdir, 'wazuh-qa'],
                                        self.system_path)},
            'become': True,
            'when': 'ansible_system != "Win32NT"'
        })

        dependencies_windows_task = AnsibleTask({
            'name': 'Install python dependencies (Windows)',
            'win_shell': 'python -m pip install -r requirements.txt',
            'args': {'chdir': join_path([self.workdir, 'wazuh-qa'],
                                        self.system_path)},
            'become': True,
            'become_method': 'runas',
            'become_user': self.ansible_admin_user,
            'when': 'ansible_system == "Win32NT"'
        })

        ansible_tasks = [dependencies_unix_task, dependencies_windows_task]
        playbook_parameters = {'hosts': hosts, 'gather_facts': True, 'tasks_list': ansible_tasks}
        QAFramework.LOGGER.debug(f"Installing python dependencies in {hosts} hosts")

        AnsibleRunner.run_ephemeral_tasks(inventory_file_path, playbook_parameters, output=self.ansible_output)

        QAFramework.LOGGER.debug(f"Python dependencies have been installed successfully in {hosts} hosts")

    def install_framework(self, inventory_file_path, hosts='all'):
        """Install the wazuh_testing framework to allow the execution of the tests.

        Args:
            inventory_file_path (str): Path were save the ansible inventory.
        """
        install_framework_unix_task = AnsibleTask({
            'name': 'Install wazuh-qa framework (Unix)',
            'shell': 'python3 setup.py install',
            'args': {'chdir': join_path([self.workdir, 'wazuh-qa', 'deps',
                                        'wazuh_testing'], self.system_path)},
            'become': True,
            'when': 'ansible_system != "Win32NT"'
        })

        install_framework_windows_task = AnsibleTask({
            'name': 'Install wazuh-qa framework (Windows)',
            'win_shell': 'python setup.py install',
            'args': {'chdir': join_path([self.workdir, 'wazuh-qa', 'deps',
                                        'wazuh_testing'], self.system_path)},
            'become': True,
            'become_method': 'runas',
            'become_user': self.ansible_admin_user,
            'when': 'ansible_system == "Win32NT"'
        })

        ansible_tasks = [install_framework_unix_task, install_framework_windows_task]
        playbook_parameters = {'hosts': hosts, 'tasks_list': ansible_tasks, 'gather_facts': True, 'become': False}
        QAFramework.LOGGER.debug(f"Installing wazuh-qa framework in {hosts} hosts.")

        AnsibleRunner.run_ephemeral_tasks(inventory_file_path, playbook_parameters, output=self.ansible_output)

        QAFramework.LOGGER.debug(f"wazuh-qa framework has been installed successfully in {hosts} hosts.")

    def download_qa_repository(self, inventory_file_path, hosts='all'):
        """Download the qa-framework in the specified attribute workdir.

        Args:
            inventory_file_path (str): Path were save the ansible inventory.
        """
        create_path_unix_task = AnsibleTask({
            'name': f"Create {self.workdir} path (Unix)",
            'file': {'path': self.workdir, 'state': 'directory', 'mode': '0755'},
            'when': 'ansible_system != "Win32NT"'
        })

        create_path_windows_task = AnsibleTask({
            'name': f"Create {self.workdir} path (Windows)",
            'win_file': {'path': self.workdir, 'state': 'directory'},
            'when': 'ansible_system == "Win32NT"'
        })

        download_qa_repo_unix_task = AnsibleTask({
            'name': f"Download {self.qa_branch} branch of wazuh-qa repository (Unix)",
            'shell': f"cd {self.workdir} && curl -Ls https://github.com/wazuh/wazuh-qa/archive/"
                     f"{self.qa_branch}.tar.gz | tar zx && mv wazuh-* wazuh-qa",
            'when': 'ansible_system != "Win32NT"'
        })

        download_qa_repo_windows_task = AnsibleTask({
            'name': f"Download {self.qa_branch} branch of wazuh-qa repository (Windows)",
            'win_shell': "powershell.exe {{ item }}",
            'with_items': [
                f"curl.exe -L https://github.com/wazuh/wazuh-qa/archive/{self.qa_branch}.tar.gz -o "
                f"{self.workdir}\\{self.qa_branch}.tar.gz",
                f"tar -xzf {self.workdir}\\{self.qa_branch}.tar.gz -C {self.workdir}",
                f"move {self.workdir}\\wazuh-qa-{self.qa_branch} {self.workdir}\\wazuh-qa",
                f"rm {self.workdir}\\{self.qa_branch}.tar.gz"
            ],
            'when': 'ansible_system == "Win32NT"'
        })

        ansible_tasks = [create_path_unix_task, create_path_windows_task, download_qa_repo_unix_task,
                         download_qa_repo_windows_task]
        playbook_parameters = {'hosts': hosts, 'gather_facts': True, 'tasks_list': ansible_tasks}
        QAFramework.LOGGER.debug(f"Downloading qa-repository in {hosts} hosts")

        AnsibleRunner.run_ephemeral_tasks(inventory_file_path, playbook_parameters, output=self.ansible_output)

        QAFramework.LOGGER.debug(f"{self.qa_branch} branch of QA repository has been downloaded successfully in "
                                 f"{hosts} hosts")
