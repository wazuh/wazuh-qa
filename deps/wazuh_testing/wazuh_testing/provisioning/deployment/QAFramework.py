from wazuh_testing.provisioning.ansible.AnsibleTask import AnsibleTask
from wazuh_testing.provisioning.ansible.AnsibleRunner import AnsibleRunner
from wazuh_testing.provisioning.ansible.AnsiblePlaybook import AnsiblePlaybook


class QAFramework():
    """Encapsulates all the functionality regarding the preparation and installation of qa-framework

    Args:
        qa_repo (str): Url to the QA repository.
        qa_branch (str): QA branch of the qa repository.
        workdir (str): Directory where the qa repository files are stored
        tests_path (str): Relative path to the set of tests to be executed.

    Attributes:
        qa_branch (str): QA branch of the qa repository.
        workdir (str): Directory where the qa repository files are stored
        tests_path (str): Relative path to the set of tests to be executed.
    """

    def __init__(self, qa_repo, qa_branch, workdir, tests_path):
        self.qa_repo = qa_repo
        self.qa_branch = qa_branch
        self.workdir = workdir
        self.tests_path = tests_path
        super().__init__()

    def install_dependencies(self, ansible_inventory_path):
        """Install all the necessary dependencies to allow the execution of the tests.

        Args:
            ansible_inventory_path (str): Path were save the ansible inventory.

        """

        ansible_playbook_path = "/tmp/ansible_playbook_install_dependencies.yaml"
        task_dependencies_python = {'shell': "apt install policycoreutils-python-utils python3-pip -y", 'args':
                                    {'chdir': self.workdir}}

        task_dependencies = {'shell': "pip3 install -r requirements.txt", 'args': {'chdir': self.workdir}}
        ansible_tasks = [AnsibleTask(task_dependencies_python), AnsibleTask(task_dependencies)]
        playbook = AnsiblePlaybook(name="install qa dependencies", tasks_list=ansible_tasks,
                                   playbook_file_path=ansible_playbook_path, become=True)
        ansible_runner = AnsibleRunner(ansible_inventory_path=ansible_inventory_path,
                                       ansible_playbook_path=ansible_playbook_path)
        try:
            ansible_runner.run()
        finally:
            playbook.delete_playbook_file()

    def install_framework(self, ansible_inventory_path):
        """Install the wazuh_testing framework to allow the execution of the tests.

        Args:
            ansible_inventory_path (str): Path were save the ansible inventory.

        """

        ansible_playbook_path = "/tmp/ansible_playbook_install_framework.yaml"
        task_install_framework = {'shell': 'pip3 install .', 'args': {'chdir': f"{self.workdir}deps/wazuh_testing"}}
        ansible_tasks = [AnsibleTask(task_install_framework)]
        playbook = AnsiblePlaybook(name="install qa-framework", tasks_list=ansible_tasks,
                                   playbook_file_path=ansible_playbook_path, become=True)
        ansible_runner = AnsibleRunner(ansible_inventory_path=ansible_inventory_path,
                                       ansible_playbook_path=ansible_playbook_path)

        try:
            ansible_runner.run()
        finally:
            playbook.delete_playbook_file()

    def download_qa_repository(self, ansible_inventory_path):
        """Downloads the qa-framework in the specified attribute workdir.

        Args:
            ansible_inventory_path (str): Path were save the ansible inventory.

        """

        ansible_playbook_path = "/tmp/ansible_playbook_download_qa.yaml"
        task_download_qa = {'git': {'repo': self.qa_repo, 'dest': self.workdir, 'version': self.qa_branch}}

        ansible_tasks = [AnsibleTask(task_download_qa)]
        playbook = AnsiblePlaybook(name="download qa repository", tasks_list=ansible_tasks,
                                   playbook_file_path=ansible_playbook_path, become=True)

        ansible_runner = AnsibleRunner(ansible_inventory_path=ansible_inventory_path,
                                       ansible_playbook_path=ansible_playbook_path)

        try:
            ansible_runner.run()
        finally:
            playbook.delete_playbook_file()

    def download_tests(self, playbook_path, tests_url, tests_path):
        pass
