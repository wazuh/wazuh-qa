import os

from tempfile import gettempdir

from wazuh_testing.qa_ctl.provisioning.ansible.AnsibleRunner import AnsibleRunner
from wazuh_testing.qa_ctl.provisioning.ansible.AnsibleTask import AnsibleTask
from wazuh_testing.tools.time import get_current_timestamp


class TestLauncher:
    """The class encapsulates the execution of a list of tests previously built and passed as a parameter.

    Attributes:
        tests (list(Test)): List containing all the tests to be executed in the remote machine
        ansible_inventory_path (str): path to the ansible inventory file
        qa_framework_path (str, None): remote directory path where the qa repository will be download to

    Args:
        tests (list(Test)): List containing all the tests to be executed in the remote machine
        ansible_inventory_path (str): path to the ansible inventory file
        qa_framework_path (str, None): remote directory path where the qa repository will be download to

    """

    DEBUG_OPTIONS = ["syscheck.debug=2", "agent.debug=2", "monitord.rotate_log=0", "analysisd.debug=2",
                     "wazuh_modules.debug=2", "wazuh_database.interval=1", "wazuh_db.commit_time=2",
                     "wazuh_db.commit_time_max=3", "remoted.debug=2"]

    def __init__(self, tests, ansible_inventory_path, qa_framework_path=None):
        self.qa_framework_path = qa_framework_path if qa_framework_path is not None else \
                                                     os.path.join(gettempdir(), 'wazuh-qa/')
        self.ansible_inventory_path = ansible_inventory_path
        self.tests = tests


    def __set_local_internal_options(self, hosts):
        """Private method that set the local internal options in the hosts passed by parameter

            Args:
                hosts (list(str)): list of hosts aliases to index the dict attribute wazuh_dir_paths and extract the
                                  wazuh installation path
        """
        local_internal_options = '\n'.join(self.DEBUG_OPTIONS)
        playbook_file_path = os.path.join(gettempdir(), f"{get_current_timestamp()}.yaml")

        local_internal_path = '/var/ossec/etc/local_internal_options.conf'

        set_local_internal_opts = {'lineinfile': {'path': local_internal_path,
                                   'line': local_internal_options}}

        ansible_tasks = [AnsibleTask(set_local_internal_opts)]

        playbook_parameters = {'become': True, 'tasks_list': ansible_tasks, 'playbook_file_path':
                               playbook_file_path, 'hosts': hosts}

        AnsibleRunner.run_ephemeral_tasks(self.ansible_inventory_path, playbook_parameters, raise_on_error=False)

    def add(self, test):
        """Add new test to the TestLauncher instance.

        Args:
            test (Test): Test object.
        """
        if test:
            self.tests.append(test)

    def run(self):
        """Function to iterate over a list of tests and run them one by one."""
        for test in self.tests:
            self.__set_local_internal_options(test.hosts)
            test.run(self.ansible_inventory_path)
