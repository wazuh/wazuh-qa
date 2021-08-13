from wazuh_testing.qa_ctl.run_tests.Pytest import Pytest


class RunQATests():
    """The class encapsulates the build of the tests from the test parameters read from the configuration file

        Args:
            test_parameters (dict): a dictionary containing all the required data to build the tests

        Attributes:
            tests (list(Pytest)): list of Pytest instances to run at the specified remote machines

    """

    def __init__(self, tests_parameters):
        self.tests = []
        for key, value in tests_parameters.items():
            self.tests.append(self.__build_test(value))

    def __build_test(self, test_params):
        """Private method in charge of reading all the required fields to build one test of type Pytest

            Args:
                test_params (dict): all the data regarding one specific test

            Returns:
                Pytest: one instance of Pytest built from the parameters in test_params
        """
        test_dict = {}

        test_dict['hosts'] = ['all'] if 'hosts' not in test_params else test_params['hosts']

        if 'path' in test_params:
            paths = test_params['path']
            test_dict['tests_path'] = paths['test_files_path']
            test_dict['tests_result_path'] = paths['test_results_path']
            test_dict['tests_run_dir'] = paths['run_tests_dir_path']

        if 'parameters' in test_params:
            parameters = test_params['parameters']
            if parameters is not None:
                test_dict['tiers'] = [] if 'tiers' not in parameters else parameters['tiers']
                test_dict['stop_after_first_failure'] = False if 'stop_after_first_failure' not in parameters \
                                                                 else parameters['stop_after_first_failure']
                test_dict['keyword_expression'] = None if 'keyword_expression' not in parameters else \
                                                          parameters['keyword_expression']
                test_dict['traceback'] = 'auto' if 'traceback' not in parameters else parameters['traceback']
                test_dict['dry_run'] = False if 'dry_run' not in parameters else parameters['dry_run']
                test_dict['custom_args'] = [] if 'custom_args' not in parameters else parameters['custom_args']
                test_dict['verbose_level'] = False if 'verbose_level' not in parameters else parameters['verbose_level']
                test_dict['log_level'] = None if 'log_level' not in parameters else parameters['log_level']
                test_dict['markers'] = [] if 'markers' not in parameters else parameters['markers']

        return Pytest(**test_dict)
