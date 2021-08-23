import os
import tempfile

from wazuh_testing.qa_ctl.provisioning.ansible.AnsibleRunner import AnsibleRunner
from wazuh_testing.qa_ctl.provisioning.ansible.AnsibleTask import AnsibleTask


class TestLauncher:
    """The class encapsulates the execution of a list of tests previously built and passed as a parameter.

    Attributes:
        tests (list(Test)): List containing all the tests to be executed in the remote machine
        wazuh_dir_paths (dict): dictionary containing a list of key-value pairs referring to host alias and wazuh
                                 installation path
        ansible_inventory_path (str): path to the ansible inventory file
        qa_framework_path (str, None): remote directory path where the qa repository will be download to

    Args:
        tests (list(Test)): List containing all the tests to be executed in the remote machine
        install_dir_paths (dict): dictionary containing a list of key-value pairs referring to host alias and wazuh
                                 installation path
        ansible_inventory_path (str): path to the ansible inventory file
        qa_framework_path (str, None): remote directory path where the qa repository will be download to

    """

    DEBUG_OPTIONS = ["syscheck.debug=2", "agent.debug=2", "monitord.rotate_log=0", "analysisd.debug=2",
                     "wazuh_modules.debug=2", "wazuh_database.interval=1", "wazuh_db.commit_time=2",
                     "wazuh_db.commit_time_max=3", "remoted.debug=2"]

    def __init__(self, tests, install_dir_paths, ansible_inventory_path,
                 qa_framework_path=None):
        self.qa_framework_path = qa_framework_path if qa_framework_path is not None else \
                                                     os.path.join(tempfile.gettempdir(), 'wazuh-qa/')
        self.ansible_inventory_path = ansible_inventory_path
        self.tests = tests
        self.wazuh_dir_paths = install_dir_paths
        self.wazuh_dir_paths.update({'all': '/var/ossec/'})

    def __set_local_internal_options(self, hosts):
        """Private method that set the local internal options in the hosts passed by parameter

            Args:
                hosts (list(str)): list of hosts aliases to index the dict attribute wazuh_dir_paths and extract the
                                  wazuh installation path
        """
        local_internal_path = ""
        local_internal_options = "\n".join(self.DEBUG_OPTIONS)
        playbook_file_path = os.path.join(tempfile.gettempdir(), 'playbook_file.yaml')

        if hosts in self.wazuh_dir_paths:
            local_internal_path += os.path.join(self.wazuh_dir_paths[hosts], '')
        else:
            local_internal_path += self.wazuh_dir_paths['all']

        local_internal_path += 'etc/local_internal_options.conf'

        set_local_internal_opts = {'lineinfile': {'path': local_internal_path,
                                   'line': local_internal_options}}

        ansible_tasks = [AnsibleTask(set_local_internal_opts)]

        playbook_parameters = {'become': True, 'tasks_list': ansible_tasks, 'playbook_file_path':
                               playbook_file_path, 'hosts': hosts}

        AnsibleRunner.run_ephemeral_tasks(self.ansible_inventory_path, playbook_parameters, raise_on_error=False)

    def run(self):
        """ Function to iterate over a list of a set of ests and execute them one by one. """
        for test in self.tests:
            self.__set_local_internal_options(test.hosts)
            test.run(self.ansible_inventory_path)
