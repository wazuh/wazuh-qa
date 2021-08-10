from datetime import datetime
import tempfile
import os

from wazuh_testing.qa_ctl.run_tests.TestResult import TestResult
from wazuh_testing.qa_ctl.provisioning.ansible.AnsibleRunner import AnsibleRunner
from wazuh_testing.qa_ctl.provisioning.ansible.AnsibleTask import AnsibleTask
from wazuh_testing.qa_ctl.run_tests.Test import Test


class Pytest(Test):
    SHELL = 'python3 -m pytest '
    """ The class encapsulates the execution options of a specified set of tests and allows running them on the
        remote host

    Attributes:
        tests_path (str): Path to the set of tests to be executed
        tests_run_dir (str): Path to the directory from where the tests are going to be executed
        tier (srt, None): List of tiers to be executed
        stop_after_first_failure (boolean, False): If set to true then the tests' execution will stop after the first failure
        keyword_expression (str, None): Regular expression allowing to execute all the tests that match said expression
        traceback (str, None): Set the traceback mode (auto/long/short/line/native/no)
        dry_run(boolean, False): If set to True the flag --collect-only is added so no test will be executed, only collected
        custom_args(dict, None): set of key pair values to be added as extra args to the test execution command
        verbose_level(boolean, False): if set to true, verbose flag is added to test execution command
        log_level(str, None): Log level to be set
        markers(list(str), None): Set of markers to be added to the test execution command

    Args:
        tests_path (str): Path to the set of tests to be executed
        tests_run_dir (str): Path to the directory from where the tests are going to be executed
        tiers (list(int), None): List of tiers to be executed
        stop_after_first_failure (boolean, False): If set to true then the tests' execution will stop after the first failure
        keyword_expression (str, None): Regular expression allowing to execute all the tests that match said expression
        traceback (str, None): Set the traceback mode (auto/long/short/line/native/no)
        dry_run(boolean, False): If set to True the flag --collect-only is added so no test will be executed, only collected
        custom_args(dict, None): set of key pair values to be added as extra args to the test execution command
        verbose_level(boolean, False): if set to true, verbose flag is added to test execution command
        log_level(str, None): Log level to be set
        markers(list(str), None): Set of markers to be added to the test execution command

    """
    def __init__(self, tests_result_path=None, tests_path=None, tests_run_dir=None, tiers=None,
                 stop_after_first_failure=False, keyword_expression=None, traceback=None, dry_run=False,
                 custom_args=None, verbose_level=False, log_level=None, markers=None, hosts="all"):

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
        super().__init__(tests_path, tests_run_dir, tests_result_path)

    def run(self, ansible_inventory_path, custom_report_file_path=None):
        """ Executes the current test with the specified options defined in attributes and bring back the reports
            to the host machine.

        Args:
            ansible_inventory_path (str): Path to ansible inventory file
            report_html_dir_path (str, None): Path to the local directory that will hold the html report
            test_output_dir_path (str, None): Path to the local directory that will hold the txt output from ansible
                                              command
        """
        assets_folder = 'assets/'
        if self.tests_result_path is None:
            self.tests_result_path = os.path.join(tempfile.gettempdir(), '')
        else:
            self.tests_result_path = os.path.join(self.tests_result_path, '')

        html_report_file_name = f"test_report-{datetime.now()}.html"
        plain_report_file_name = f"plain_report-{datetime.now()}.txt"

        shell = self.SHELL

        if self.keyword_expression:
            shell += os.path.join(self.tests_path, self.keyword_expression) + " "
        else:
            shell += self.tests_path + " "
        if self.tiers:
            shell += ' '.join([f"--tier={tier}" for tier in self.tiers]) + ' '
        if self.dry_run:
            shell += '--collect-only '
        if self.stop_after_first_failure:
            shell += '-x '
        if self.verbose_level:
            shell += '--verbose '
        if self.custom_args:
            for custom_arg in self.custom_args:
                shell += f"--metadata {custom_arg} "
        if self.log_level:
            shell += f"--log-level={self.log_level} "
        if self.traceback:
            shell += f"--tb={self.traceback} "
        if self.markers:
            shell += f"-m {' '.join(self.markers)} "
        shell += f"--html='./{html_report_file_name}'"

        execute_test_task = {'shell': shell, 'vars':
                             {'chdir': self.tests_run_dir},
                             'register': 'test_output',
                             'ignore_errors': 'yes'}

        create_plain_report = {'copy': {'dest': os.path.join(self.tests_run_dir, plain_report_file_name),
                                        'content': "{{test_output.stdout}}"}}

        fetch_plain_report = {'fetch': {'src': os.path.join(self.tests_run_dir, plain_report_file_name),
                                        'dest': self.tests_result_path, 'flat': 'yes'}}

        fetch_html_report = {'fetch': {'src': os.path.join(self.tests_run_dir, html_report_file_name),
                                       'dest': self.tests_result_path, 'flat': 'yes'}}

        ansible_tasks = [AnsibleTask(execute_test_task), AnsibleTask(create_plain_report),
                         AnsibleTask(fetch_plain_report), AnsibleTask(fetch_html_report)]

        playbook_parameters = {'become': True, 'tasks_list': ansible_tasks, 'playbook_file_path':
                               '/tmp/playbook_file.yaml', "hosts": self.hosts}

        AnsibleRunner.run_ephemeral_tasks(ansible_inventory_path, playbook_parameters, raise_on_error=False)

        # copy assets directory to local machine

        check_assets_directory_exists = {'local_action': f"stat \
                                         path={os.path.join(self.tests_result_path, assets_folder)}",
                                         'register': 'stat_assets_folder'}

        create_assets_directory = {'local_action': f"ansible.builtin.command mkdir \
                                                   {os.path.join(self.tests_result_path, assets_folder)}",
                                   'when': 'stat_assets_folder.stat.exists == False'}

        fetch_assets_files = {'ansible.posix.synchronize': {'src': os.path.join(self.tests_run_dir, assets_folder),
                                                            'dest': os.path.join(self.tests_result_path, assets_folder),
                                                            'mode': 'pull',
                                                            'delete': 'yes'
                                                            }}
        ansible_tasks = [AnsibleTask(check_assets_directory_exists), AnsibleTask(create_assets_directory),
                         AnsibleTask(fetch_assets_files)]

        playbook_parameters = {'become': False, 'tasks_list': ansible_tasks, 'playbook_file_path':
                               '/tmp/playbook_file.yaml', "hosts": self.hosts}

        AnsibleRunner.run_ephemeral_tasks(ansible_inventory_path, playbook_parameters, raise_on_error=False)

        self.result = TestResult(html_report_file_path=os.path.join(self.tests_result_path, html_report_file_name),
                                 plain_report_file_path=os.path.join(self.tests_result_path, plain_report_file_name))
