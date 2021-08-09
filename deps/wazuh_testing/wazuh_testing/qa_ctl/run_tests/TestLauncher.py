import os

from wazuh_testing.qa_ctl.provisioning.ansible.AnsibleRunner import AnsibleRunner
from wazuh_testing.qa_ctl.provisioning.ansible.AnsibleTask import AnsibleTask


class TestLauncher:
    DEBUG_OPTIONS = ["syscheck.debug=2", "agent.debug=2", "monitord.rotate_log=0", "analysisd.debug=2",
                     "wazuh_modules.debug=2", "wazuh_database.interval=1", "wazuh_db.commit_time=2",
                     "wazuh_db.commit_time_max=3", "remoted.debug=2"]
    """ The class encapsulates the execution of a list of tests previously built and passed as a parameter.

    Attributes:
        tests_path (str): Path to the set of tests to be executed
        tests_run_dir (str): Path to the directory from where the tests are going to be executed
        ansible_inventory_path (str): Path to the ansible inventory file
        tests (list(Test)): List containing all the tests to be executed in the remote machine
        html_report_dir_path (str, None): Local directory path where the html report will be stored
        test_output_dir_path (str, None):  Local directory path where the plain report will be stored
        qa_framework_path (str, None): Remote directory path where the qa repository will be download to

    Args:
        tests_path (str): Path to the set of tests to be executed
        tests_run_dir (str): Path to the directory from where the tests are going to be executed
        ansible_inventory_path (str): Path to the ansible inventory file
        tests (list(Test)): List containing all the tests to be executed in the remote machine
        html_report_dir_path (str, None): Local directory path where the html report will be stored
        test_output_dir_path (str, None):  Local directory path where the plain report will be stored
        qa_framework_path (str, None): Remote directory path where the qa repository will be download to

    """
    def __init__(self, tests, install_dir_paths, ansible_inventory_path='/tmp/inventory.yaml',
                 qa_framework_path="/tmp/wazuh-qa/"):
        self.qa_framework_path = qa_framework_path
        self.ansible_inventory_path = ansible_inventory_path
        self.tests = tests
        self.wazuh_dir_paths = install_dir_paths
        self.wazuh_dir_paths.update({'all': '/var/ossec/'})

    def __set_local_internal_options(self, hosts):
        local_internal_path = ""
        local_internal_options = "\n".join(self.DEBUG_OPTIONS)

        if hosts in self.wazuh_dir_paths:
            local_internal_path += os.path.join(self.wazuh_dir_paths[hosts], '')
        else:
            local_internal_path += self.wazuh_dir_paths['all']

        local_internal_path += "etc/local_internal_options.conf"

        set_local_internal_opts = {'lineinfile': {'path': local_internal_path,
                                   'line': local_internal_options}}

        ansible_tasks = [AnsibleTask(set_local_internal_opts)]

        playbook_parameters = {'become': True, 'tasks_list': ansible_tasks, 'playbook_file_path':
                               '/tmp/playbook_file.yaml', 'hosts': hosts}

        AnsibleRunner.run_ephemeral_tasks(self.ansible_inventory_path, playbook_parameters, raise_on_error=False)

    def run(self):
        """ Function to iterate over a list of a set of ests and execute them one by one. """
        for test in self.tests:
            self.__set_local_internal_options(test.hosts)
            test.run(self.ansible_inventory_path)
