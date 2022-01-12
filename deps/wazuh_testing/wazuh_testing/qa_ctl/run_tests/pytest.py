import os
import re
from datetime import datetime
from tempfile import gettempdir

from wazuh_testing.qa_ctl.run_tests.test_result import TestResult
from wazuh_testing.qa_ctl.provisioning.ansible.ansible_runner import AnsibleRunner
from wazuh_testing.qa_ctl.provisioning.ansible.ansible_task import AnsibleTask
from wazuh_testing.qa_ctl.run_tests.test import Test
from wazuh_testing.tools.time import get_current_timestamp
from wazuh_testing.qa_ctl import QACTL_LOGGER
from wazuh_testing.tools.logging import Logging
from wazuh_testing.tools.file import join_path


class Pytest(Test):
    """The class encapsulates the execution options of a specified set of tests and allows running them on the
       remote host

    Args:
        tests_result_path(str): Path to the directory where the reports will be stored in the local machine
        tests_path (str): Path to the set of tests to be executed
        tests_run_dir (str): Path to the directory from where the tests are going to be executed
        qa_ctl_configuration (QACTLConfiguration): QACTL configuration.
        tiers (list(int), []): List of tiers to be executed
        stop_after_first_failure (boolean, False): If set to true then the tests' execution will stop after the first
                                                  failure
        keyword_expression (str, None): Regular expression allowing to execute all the tests that match said expression
        traceback (str, 'auto): Set the traceback mode (auto/long/short/line/native/no)
        dry_run(boolean, False): If set to True the flag --collect-only is added so no test will be executed, only
                                collected
        custom_args(list(str), []): set of key pair values to be added as extra args to the test execution command
        verbose_level(boolean, False): if set to true, verbose flag is added to test execution command
        log_level(str, None): Log level to be set
        markers(list(str), []): Set of markers to be added to the test execution command
        hosts(list(), ['all']): List of hosts aliases where the tests will be runned
        modules (list(str)): List of wazuh modules to which the test belongs.
        component (str): Test target (manager, agent).
        system (str): System where the test will be launched.
        wazuh_install_path (str): Wazuh installation directory p.e /var/ossec.

    Attributes:
        tests_result_path(str): Path to the directory where the reports will be stored in the local machine
        tests_path (str): Path to the set of tests to be executed
        tests_run_dir (str): Path to the directory from where the tests are going to be executed
        qa_ctl_configuration (QACTLConfiguration): QACTL configuration.
        tier (srt, None): List of tiers to be executed
        stop_after_first_failure (boolean, False): If set to true then the tests' execution will stop after the first
                                                  failure
        keyword_expression (str, None): Regular expression allowing to execute all the tests that match said expression
        traceback (str, None): Set the traceback mode (auto/long/short/line/native/no)
        dry_run(boolean, False): If set to True the flag --collect-only is added so no test will be executed, only
                                collected
        custom_args(dict, None): set of key pair values to be added as extra args to the test execution command
        verbose_level(boolean, False): if set to true, verbose flag is added to test execution command
        log_level(str, None): Log level to be set
        markers(list(str), None): Set of markers to be added to the test execution command
        hosts(list(), ['all']): List of hosts aliases where the tests will be runned
        wazuh_install_path (str): Wazuh installation directory p.e /var/ossec.
    """
    RUN_PYTEST_UNIX = 'python3 -m pytest '
    RUN_PYTEST_WINDOWS = 'python -m pytest '
    LOGGER = Logging.get_logger(QACTL_LOGGER)

    def __init__(self, tests_result_path, tests_path, tests_run_dir, qa_ctl_configuration,
                 tiers=[], stop_after_first_failure=False, keyword_expression=None, traceback='auto', dry_run=False,
                 custom_args=[], verbose_level=False, log_level=None, markers=[], hosts=['all'], modules=None,
                 component=None, system='linux', wazuh_install_path=None, ansible_admin_user=None):
        self.qa_ctl_configuration = qa_ctl_configuration
        self.tiers = tiers
        self.stop_after_first_failure = stop_after_first_failure
        self.keyword_expression = keyword_expression
        self.traceback = traceback
        self.dry_run = dry_run
        self.custom_args = custom_args
        self.verbose_level = verbose_level
        self.log_level = log_level
        self.markers = markers
        self.hosts = hosts
        self.wazuh_install_path = wazuh_install_path
        self.ansible_admin_user = ansible_admin_user
        self.tests_result_path = os.path.join(gettempdir(), 'wazuh_qa_ctl') if tests_result_path is None \
            else tests_result_path

        if not os.path.exists(self.tests_result_path):
            os.makedirs(self.tests_result_path)

        super().__init__(tests_path, tests_run_dir, tests_result_path, modules, component, system)

    def __output_trimmer(self, result):
        """This function trims the obtained results in order to get a more readable output information
            when executing qa-ctl

        Args:
            result (Test resutl object): object containing all the results obtained from the test

        Return:
            output_result (string): String containing the trimmed output
        """
        output_result = str(result)
        error_fail_pattern = re.compile('^=*.(ERRORS|FAILURES).*=$', re.M)
        test_summary_pattern = re.compile('^=*.(short test summary info).*=$', re.M)

        # Check for any error or failure message case in the test result output
        error_case = re.search(error_fail_pattern, output_result)
        if error_case is not None:
            # Checks if there is any test summary info at the end of the result output
            test_summary_case = re.search(test_summary_pattern, output_result)
            test_summary_output = ''
            if test_summary_case is not None:
                test_result_message = test_summary_case.group(0)
                test_summary_output = output_result[output_result.index(test_result_message):]

            error_case_message = error_case.group(0)
            output_result = output_result[:output_result.index(error_case_message)]
            output_result += test_summary_output

        return output_result

    def run(self, ansible_inventory_path):
        """Executes the current test with the specified options defined in attributes and bring back the reports
            to the host machine.

        Args:
            ansible_inventory_path (str): Path to ansible inventory file
        """
        date_time = datetime.now().strftime('%Y_%m_%d_%H_%M_%S_%f')
        assets_folder = 'assets/'
        reports_folder = 'reports'
        assets_zip = f"assets_{date_time}.zip"
        html_report_file_name = f"test_report_{date_time}.html"
        plain_report_file_name = f"test_report_{date_time}.txt"
        playbook_file_path = os.path.join(gettempdir(), 'wazuh_qa_ctl', f"{get_current_timestamp()}.yaml")
        reports_directory = join_path([self.tests_run_dir, reports_folder], self.system)
        plain_report_file_path = os.path.join(reports_directory, plain_report_file_name)
        html_report_file_path = os.path.join(reports_directory, html_report_file_name)
        assets_src_directory = os.path.join(reports_directory, assets_folder)
        zip_src_path = os.path.join(reports_directory, assets_zip)

        pytest_command = self.RUN_PYTEST_WINDOWS if self.system == 'windows' else self.RUN_PYTEST_UNIX

        if self.keyword_expression:
            pytest_command += os.path.join(self.tests_path, self.keyword_expression) + " "
        else:
            pytest_command += self.tests_path + " "
        if self.tiers:
            pytest_command += ' '.join([f"--tier={tier}" for tier in self.tiers]) + ' '
        if self.dry_run:
            pytest_command += '--collect-only '
        if self.stop_after_first_failure:
            pytest_command += '-x '
        if self.verbose_level:
            pytest_command += '--verbose '
        if self.custom_args:
            for custom_arg in self.custom_args:
                pytest_command += f"--metadata {custom_arg} "
        if self.log_level:
            pytest_command += f"--log-level={self.log_level} "
        if self.traceback:
            pytest_command += f"--tb={self.traceback} "
        if self.markers:
            pytest_command += f"-m {' '.join(self.markers)} "

        pytest_command += f"--html='{os.path.join(reports_directory, html_report_file_name)}'"

        create_path_task_unix = {
            'name': f"Create {reports_directory} path (Unix)",
            'file': {'path': reports_directory, 'state': 'directory', 'mode': '0755'},
            'become': True,
            'when': 'ansible_system != "Win32NT"'
        }

        create_path_task_windows = {
            'name': f"Create {reports_directory} path (Windows)",
            'win_file': {'path': reports_directory, 'state': 'directory'},
            'become': True,
            'become_method': 'runas',
            'become_user': self.ansible_admin_user,
            'when': 'ansible_system == "Win32NT"'
        }

        run_test_task_unix = {
            'name': f"Launch pytest in {self.tests_run_dir} (Unix)",
            'shell': pytest_command, 'args': {'chdir': self.tests_run_dir},
            'register': 'test_output_unix',
            'ignore_errors': 'yes',
            'become': True,
            'when': 'ansible_system != "Win32NT"'
        }

        run_test_task_windows = {
            'name': f"Launch pytest in {self.tests_run_dir} (Windows)",
            'win_shell': pytest_command, 'args': {'chdir': self.tests_run_dir},
            'register': 'test_output_windows',
            'ignore_errors': 'yes',
            'become': True,
            'become_method': 'runas',
            'become_user': self.ansible_admin_user,
            'when': 'ansible_system == "Win32NT"'
        }

        create_plain_report_unix = {
            'name': f"Create plain report file in {plain_report_file_path} (Unix)",
            'copy': {'dest': plain_report_file_path, 'content': "{{test_output_unix.stdout}}"},
            'become': True,
            'when': 'ansible_system != "Win32NT"'
        }

        create_plain_report_windows = {
            'name': f"Create plain report file in {plain_report_file_path} (Windows)",
            'win_copy': {'dest': plain_report_file_path, 'content': "{{test_output_windows.stdout}}"},
            'become': True,
            'become_method': 'runas',
            'become_user': self.ansible_admin_user,
            'when': 'ansible_system == "Win32NT"'
        }

        fetch_plain_report = {
            'name': f"Move {plain_report_file_name} from {plain_report_file_path} to {self.tests_result_path}",
            'fetch': {'src': plain_report_file_path, 'dest': f"{self.tests_result_path}/", 'flat': 'yes'}
        }

        fetch_html_report = {
            'name': f"Move {html_report_file_name} from {html_report_file_path} to {self.tests_result_path}",
            'fetch': {'src': html_report_file_path, 'dest': f"{self.tests_result_path}/", 'flat': 'yes'},
            'ignore_errors': 'yes'
        }

        compress_assets_folder_unix = {
            'name': "Compress assets folder (Unix)",
            'community.general.archive': {'path': assets_src_directory, 'dest': zip_src_path, 'format': 'zip'},
            'ignore_errors': 'yes',
            'become': True,
            'when': 'ansible_system != "Win32NT"'
        }

        compress_assets_folder_windows = {
            'name': "Compress assets folder (Windows)",
            'win_shell': f"powershell.exe Compress-Archive {assets_src_directory} {zip_src_path}",
            'ignore_errors': 'yes',
            'become': True,
            'become_method': 'runas',
            'become_user': self.ansible_admin_user,
            'when': 'ansible_system == "Win32NT"'
        }

        fetch_compressed_assets = {
            'name': f"Copy compressed assets from {zip_src_path} to {self.tests_result_path}",
            'fetch': {'src': zip_src_path, 'dest': f"{self.tests_result_path}/", 'flat': 'yes'},
            'ignore_errors': 'yes'
        }

        ansible_tasks = [
            AnsibleTask(create_path_task_unix), AnsibleTask(create_path_task_windows),
            AnsibleTask(run_test_task_unix), AnsibleTask(run_test_task_windows),
            AnsibleTask(create_plain_report_unix), AnsibleTask(create_plain_report_windows),
            AnsibleTask(fetch_plain_report), AnsibleTask(fetch_html_report),  AnsibleTask(compress_assets_folder_unix),
            AnsibleTask(compress_assets_folder_windows), AnsibleTask(fetch_compressed_assets)
        ]

        playbook_parameters = {
            'become': False, 'tasks_list': ansible_tasks, 'playbook_file_path': playbook_file_path, "hosts": self.hosts,
            'gather_facts': True
        }

        Pytest.LOGGER.info(f"Running {self.tests_path} test on {self.hosts} hosts")
        Pytest.LOGGER.debug(f"Running {pytest_command} on {self.hosts} hosts")

        AnsibleRunner.run_ephemeral_tasks(ansible_inventory_path, playbook_parameters, raise_on_error=False,
                                          output=self.qa_ctl_configuration.ansible_output)

        self.result = TestResult(html_report_file_path=os.path.join(self.tests_result_path, html_report_file_name),
                                 plain_report_file_path=os.path.join(self.tests_result_path, plain_report_file_name),
                                 test_name=self.tests_path)

        # Trim the result report for a more simple and readable output
        if Pytest.LOGGER.level != 10:
            output_result = self.__output_trimmer(self.result)
        else:
            output_result = str(self.result)

        # Print test result in stdout
        if self.qa_ctl_configuration.logging_enable:
            if os.path.exists(self.result.plain_report_file_path):
                Pytest.LOGGER.info(output_result)
            else:
                Pytest.LOGGER.error(f"Test results could not be saved in {self.result.plain_report_file_path} file")
        else:
            if os.path.exists(self.result.plain_report_file_path):
                print(output_result)
            else:
                print(f"Test results could not be saved in {self.result.plain_report_file_path} file")
