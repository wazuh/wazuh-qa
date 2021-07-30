from datetime import datetime
import tempfile
import os

from wazuh_testing.provisioning.tests.TestResult import TestResult
from wazuh_testing.provisioning.ansible.AnsibleRunner import AnsibleRunner
from wazuh_testing.provisioning.ansible.AnsibleTask import AnsibleTask
from wazuh_testing.provisioning.tests.Test import Test


class Pytest(Test):
    """ The class encapsulates the execution options of an especified set of tests and allows running them on the
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
                 custom_args=None, verbose_level=False, log_level=None, markers=None):

        self.tiers = tiers
        self.stop_after_first_failure = stop_after_first_failure
        self.keyword_expression = keyword_expression
        self.traceback = traceback
        self.dry_run = dry_run
        self.custom_args = custom_args
        self.verbose_level = verbose_level
        self.log_level = log_level
        self.markers = markers

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

        if self.tests_result_path is None:
            self.tests_result_path = os.path.join(tempfile.gettempdir(), '')

        # if not custom_report_file_path:
        #    custom_report_file_path = os.path.join(self.tests_result_path, f"custom-report-{datetime.now()}")

        html_report_file_name = f"test_report-{datetime.now()}.html"
        plain_report_file_name = f"plain_report-{datetime.now()}.txt"

        shell = "python3 -m pytest "

        if self.keyword_expression:
            shell += os.path.join(self.tests_path, self.keyword_expression) + " "
        else:
            shell += self.tests_path + " "

        if self.tiers:
            shell += ' '.join(['--tier='+str(tier) for tier in self.tiers]) + ' '
        if self.dry_run:
            shell += "--collect-only "
        if self.stop_after_first_failure:
            shell += "-x "
        if self.verbose_level:
            shell += "--verbose "
        if self.custom_args:
            for key, value in self.custom_args:
                shell += f"--metadata={key} {value} "
        if self.log_level:
            shell += f"--log-level={self.log_level} "
        if self.markers:
            shell += f"markers {self.markers} "
        if self.traceback:
            shell += f"--tb={self.traceback} "

        shell += f"--html='./{html_report_file_name}' --self-contained-html"

        execute_test_task = {'shell': shell, 'vars':
                             {'chdir': self.tests_run_dir},
                             'register': 'test_output'}

        create_plain_report = {'copy': {'dest': os.path.join(self.tests_run_dir,
                               plain_report_file_name), 'content': "{{test_output.stdout}}"}}

        fetch_plain_report = {'fetch': {'src': os.path.join(self.tests_run_dir, plain_report_file_name),
                              'dest': self.tests_result_path, 'flat': 'yes'}}

        fetch_html_report = {'fetch': {'src': os.path.join(self.tests_run_dir, html_report_file_name),
                             'dest': self.tests_result_path, 'flat': 'yes'}}

        ansible_tasks = [AnsibleTask(execute_test_task), AnsibleTask(create_plain_report),
                         AnsibleTask(fetch_plain_report), AnsibleTask(fetch_html_report)]

        playbook_parameters = {'become': True, 'tasks_list': ansible_tasks, 'playbook_file_path':
                               '/tmp/playbook_file.yaml'}

        AnsibleRunner.run_ephemeral_tasks(ansible_inventory_path, playbook_parameters)

        self.result = TestResult(html_report_file_path=os.path.join(self.tests_result_path, html_report_file_name),
                                 plain_report_file_path=os.path.join(self.tests_result_path, plain_report_file_name))
