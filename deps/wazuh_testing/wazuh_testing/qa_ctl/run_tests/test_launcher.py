import os
from tempfile import gettempdir

from wazuh_testing.qa_ctl.provisioning.ansible.ansible_runner import AnsibleRunner
from wazuh_testing.qa_ctl.provisioning.ansible.ansible_task import AnsibleTask
from wazuh_testing.tools.time import get_current_timestamp
from wazuh_testing.qa_ctl import QACTL_LOGGER
from wazuh_testing.tools.logging import Logging


class TestLauncher:
    """The class encapsulates the execution of a list of tests previously built and passed as a parameter.

    Attributes:
        tests (list(Test)): List containing all the tests to be executed in the remote machine
        ansible_inventory_path (str): path to the ansible inventory file
        qa_ctl_configuration (QACTLConfiguration): QACTL configuration.
        qa_framework_path (str, None): remote directory path where the qa repository will be download to

    Args:
        tests (list(Test)): List containing all the tests to be executed in the remote machine
        ansible_inventory_path (str): path to the ansible inventory file
        qa_ctl_configuration (QACTLConfiguration): QACTL configuration.
        qa_framework_path (str, None): remote directory path where the qa repository will be download to
    """
    LOGGER = Logging.get_logger(QACTL_LOGGER)
    ALL_DEBUG_OPTIONS = ["syscheck.debug=2", "agent.debug=2", "monitord.rotate_log=0", "analysisd.debug=2",
                         "wazuh_modules.debug=2", "wazuh_database.interval=1", "wazuh_db.commit_time=2",
                         "wazuh_db.commit_time_max=3", "remoted.debug=2"]
    DEBUG_OPTIONS = {
        'active_response': {
            'manager': ['monitord.rotate_log=0'],
            'agent': {
                'generic': ['monitord.rotate_log=0'],
                'windows': ['monitord.rotate_log=0']
            }
        },
        'agentd': {
            'agent': {
                'generic': ['agent.debug=2', 'execd.debug=2', 'monitord.rotate_log=0'],
                'windows': ['agent.debug=2', 'execd.debug=2', 'monitord.rotate_log=0']
            }
        },
        'analysisd': {
            'manager': ['analysisd.debug=2', 'monitord.rotate_log=0']
        },
        'api': {
            'manager': ['monitord.rotate_log=0']
        },
        'fim': {
            'manager': ['syscheck.debug=2', 'analysisd.debug=2', 'monitord.rotate_log=0'],
            'agent': {
                'generic': ['syscheck.debug=2', 'agent.debug=2', 'monitord.rotate_log=0'],
                'windows': ['syscheck.debug=2', 'agent.debug=2', 'monitord.rotate_log=0']
            }
        },
        'gcloud': {
            'manager': ['analysisd.debug=2', 'wazuh_modules.debug=2', 'monitord.rotate_log=0']
        },
        'logtest': {
            'manager': ['analysisd.debug=2']
        },
        'remoted': {
            'manager': ['remoted.debug=2', 'wazuh_database.interval=1', 'wazuh_db.commit_time=2',
                        'wazuh_db.commit_time_max=3', 'monitord.rotate_log=0']
        },
        'vulnerability_detector': {
            'manager': ['wazuh_modules.debug=2', 'monitord.rotate_log=0']
        },
        'wazuh_db': {
            'manager': ['wazuh_modules.debug=2', 'monitord.rotate_log=0']
        },
        'wpk': {
            'manager': ['wazuh_modules.debug=2'],
            'agent': {
                'generic': ['wazuh_modules.debug=2'],
                'windows': ['windows.debug=2']
            }
        }
    }

    def __init__(self, tests, ansible_inventory_path, qa_ctl_configuration, qa_framework_path=None):
        self.qa_framework_path = qa_framework_path if qa_framework_path is not None else \
                                                     os.path.join(gettempdir(), 'wazuh_qa_ctl', 'wazuh-qa')
        self.ansible_inventory_path = ansible_inventory_path
        self.qa_ctl_configuration = qa_ctl_configuration
        self.tests = tests

    def __set_local_internal_options(self, hosts, modules, component, system, wazuh_install_path, ansible_admin_user):
        """Private method that set the local internal options in the hosts passed by parameter

            Args:
                hosts (list(str)): list of hosts aliases to index the dict attribute wazuh_dir_paths and extract the
                                   wazuh installation path.
                modules (list(str)): List of wazuh modules to which the test belongs.
                component (str): Test wazuh target (manager, agent).
                system (str): System where the test will be launched.
                wazuh_install_path (str): Wazuh installation directory p.e /var/ossec.
                ansible_admin_user (str): User to launch the ansible task with admin privileges (ansible_become_user)
        """
        local_internal_options_content = []
        system = 'windows' if system == 'windows' else 'generic'

        if isinstance(modules, list) and len(modules) > 0 and component:
            for module in modules:
                if component == 'agent':
                    local_internal_options_content.extend(self.DEBUG_OPTIONS[module][component][system])
                else:
                    local_internal_options_content.extend(self.DEBUG_OPTIONS[module][component])

            # Delete duplicated items
            local_internal_options_content = list(set(local_internal_options_content))
        else:
            local_internal_options_content = self.ALL_DEBUG_OPTIONS

        playbook_file_path = os.path.join(gettempdir(), 'wazuh_qa_ctl' f"{get_current_timestamp()}.yaml")

        if system == 'windows':
            local_internal_options_path = f"{wazuh_install_path}\\local_internal_options.conf"
        else:
            local_internal_options_path = f"{wazuh_install_path}/etc/local_internal_options.conf"

        clean_local_internal_configuration_unix = {
            'name': 'Clean local internal configuration (Unix)',
            'copy': {'dest': local_internal_options_path, 'content': ''},
            'become': True,
            'when': 'ansible_system != "Win32NT"'
        }

        clean_local_internal_configuration_windows = {
            'name': 'Clean local internal configuration (Windows)',
            'win_copy': {'dest': local_internal_options_path, 'content': ''},
            'become': True,
            'become_method': 'runas',
            'become_user': ansible_admin_user,
            'when': 'ansible_system == "Win32NT"'
        }

        set_local_internal_configuration_unix = {
            'name': 'Set custom local internal configuration (Unix)',
            'lineinfile': {'path': local_internal_options_path, 'line': "{{ item }}"},
            'with_items': local_internal_options_content,
            'become': True,
            'when': 'ansible_system != "Win32NT"'
        }

        set_local_internal_configuration_windows = {
            'name': 'Set custom local internal configuration (Windows)',
            'win_lineinfile': {'path': local_internal_options_path, 'line': "{{ item }}"},
            'with_items': local_internal_options_content.copy(),
            'become': True,
            'become_method': 'runas',
            'become_user': ansible_admin_user,
            'when': 'ansible_system == "Win32NT"'
        }

        ansible_tasks = [
            AnsibleTask(clean_local_internal_configuration_unix),
            AnsibleTask(clean_local_internal_configuration_windows),
            AnsibleTask(set_local_internal_configuration_unix),
            AnsibleTask(set_local_internal_configuration_windows)
        ]

        playbook_parameters = {'become': False, 'gather_facts': True, 'tasks_list': ansible_tasks,
                               'playbook_file_path': playbook_file_path, 'hosts': hosts}

        TestLauncher.LOGGER.debug(f"Setting local_internal_options configuration in {hosts} hosts with "
                                  f"{local_internal_options_content}")
        AnsibleRunner.run_ephemeral_tasks(self.ansible_inventory_path, playbook_parameters, raise_on_error=False,
                                          output=self.qa_ctl_configuration.ansible_output)

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
            self.__set_local_internal_options(test.hosts, test.modules, test.component, test.system,
                                              test.wazuh_install_path, test.ansible_admin_user)
            test.run(self.ansible_inventory_path)
