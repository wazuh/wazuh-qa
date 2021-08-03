import yaml
import sys

from tests.Pytest import Pytest
from tests.TestLauncher import TestLauncher


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

    def parse_tests_definition_file(self):

        tests = []
        with open(self.def_tests_file) as tests_file:
            try:
                tests_obj = yaml.safe_load(tests_file)
            except yaml.YAMLError as yaml_e:
                print(f"Error while parsing: {yaml_e}", file=sys.stderr)
                exit()

            try:
                if 'tests' in tests_obj:
                    for key, value in tests_obj['tests'].items():
                        tests.append(self.__build_test(value))
                else:
                    print("Malformed document. No tests root key found.")
                    exit()

            except KeyError as e:
                print(f'Keyword error. Bad tag in document:  {e}')
                exit()

        return tests

    def __init__(self, def_tests_file):
        self.def_tests_file = def_tests_file


run_pytest = RunQATests('tests/tests_def_file.yaml')

tests = run_pytest.parse_tests_definition_file()

test_launcher = TestLauncher('/tmp/ansible_inventory.yaml', tests=tests)

test_launcher.run()
