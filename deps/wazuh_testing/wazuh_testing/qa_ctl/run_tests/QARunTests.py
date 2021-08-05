import yaml
import sys

from wazuh_testing.qa_ctl.run_tests.Pytest import Pytest
from wazuh_testing.qa_ctl.run_tests.TestLauncher import TestLauncher


class RunQATests():

    def __build_test(self, test_params):
        test_dict = {}
        if 'path' in test_params:
            paths = test_params['path']
            test_dict['tests_path'] = paths['test_files_path']
            test_dict['tests_result_path'] = paths['test_results_path']
            test_dict['tests_run_dir'] = paths['run_tests_dir_path']

        if 'parameters' in test_params:
            parameters = test_params['parameters']
            test_dict['tiers'] = parameters['tiers']
            test_dict['stop_after_first_failure'] = parameters['stop_after_first_failure']
            test_dict['keyword_expression'] = parameters['keyword_expression']
            test_dict['traceback'] = parameters['traceback']
            test_dict['dry_run'] = parameters['dry_run']
            test_dict['custom_args'] = parameters['custom_args']
            test_dict['verbose_level'] = parameters['verbose_level']
            test_dict['log_level'] = parameters['log_level']
            test_dict['markers'] = parameters['markers']

        return Pytest(**test_dict)

    def __init__(self, tests_obj):
        self.tests = []
        try:
            if 'tests' in tests_obj:
                for key, value in tests_obj['tests'].items():
                    self.tests.append(self.__build_test(value))
            else:
                print("Malformed document. No tests root key found.")
                exit()

        except KeyError as e:
            print(f'Keyword error. Bad tag in document:  {e}')
            exit()
