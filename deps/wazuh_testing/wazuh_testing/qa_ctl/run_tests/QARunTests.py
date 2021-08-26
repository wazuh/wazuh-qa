from wazuh_testing.qa_ctl.provisioning.ansible.AnsibleInstance import AnsibleInstance
from wazuh_testing.qa_ctl.provisioning.ansible.AnsibleInventory import AnsibleInventory
from wazuh_testing.qa_ctl.run_tests.TestLauncher import TestLauncher
from wazuh_testing.qa_ctl.run_tests.Pytest import Pytest
from wazuh_testing.tools.thread_executor import ThreadExecutor
from wazuh_testing.qa_ctl import QACTL_LOGGER
from wazuh_testing.tools.logging import Logging


class RunQATests():
    """The class encapsulates the build of the tests from the test parameters read from the configuration file

        Args:
            test_parameters (dict): a dictionary containing all the required data to build the tests

        Attributes:
            inventory_file_path (string): Path of the inventory file generated.
            test_launchers (list(TestLauncher)): Test launchers objects (one for each host).
    """
    LOGGER = Logging.get_logger(QACTL_LOGGER)

    def __init__(self, tests_parameters):
        self.inventory_file_path = None
        self.test_launchers = []
        self.__process_inventory_data(tests_parameters)
        self.__process_test_data(tests_parameters)


    def __read_ansible_instance(self, host_info):
        """Read every host info and generate the AnsibleInstance object.

        Attributes:
            host_info (dict): Dict with the host info needed coming from config file.

        Returns:
            instance (AnsibleInstance): Contains the AnsibleInstance for a given host.
        """
        extra_vars = None if 'host_vars' not in host_info else host_info['host_vars']
        private_key_path = None if 'local_private_key_file_path' not in host_info \
                                   else host_info['local_private_key_file_path']
        instance = AnsibleInstance(host=host_info['host'], host_vars=extra_vars,
                                   connection_method=host_info['connection_method'],
                                   connection_port=host_info['connection_port'], connection_user=host_info['user'],
                                   connection_user_password=host_info['password'],
                                   ssh_private_key_file_path=private_key_path,
                                   ansible_python_interpreter=host_info['ansible_python_interpreter'])
        return instance

    def __process_inventory_data(self, instances_info):
        """Process config file info to generate the ansible inventory file.

         Args:
            instances_info (dict): Dictionary with hosts configuration.
        """
        RunQATests.LOGGER.debug('Processing inventory data from testing hosts info...')
        instances_list = []

        for _, host_value in instances_info.items():
            for module_key, module_value in host_value.items():
                if module_key == 'host_info':
                    current_host = module_value['host']
                    if current_host:
                        instances_list.append(self.__read_ansible_instance(module_value))

        inventory_instance = AnsibleInventory(ansible_instances=instances_list)
        self.inventory_file_path = inventory_instance.inventory_file_path


    def __process_test_data(self, instances_info):
        """Process test data configuration and build the test launchers, setting the related class attribute.

        Args:
            instances_info (dict): Dictionary with hosts configuration.
        """
        RunQATests.LOGGER.debug('Processing testing data from hosts..')

        for _, host_value in instances_info.items():
            test_launcher = TestLauncher([], self.inventory_file_path)
            for module_key, module_value in host_value.items():
                hosts = host_value['host_info']['host']
                if module_key == 'test':
                    test_launcher.add(self.__build_test(module_value, hosts))
            self.test_launchers.append(test_launcher)


    def __build_test(self, test_params, host=['all']):
        """Private method in charge of reading all the required fields to build one test of type Pytest

            Args:
                test_params (dict): all the data regarding one specific test
                host: Host IP where the test will be run

            Returns:
                Pytest: one instance of Pytest built from the parameters in test_params
        """
        if test_params['type'] == 'pytest':
            test_dict = {}
            test_dict['hosts'] = [host]

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
        else:
            raise ValueError(f"Test \'{test_params['type']}\' is not allowed. Allowed value: pytest")

    def run(self):
        """Run testing threads. One thread per TestLauncher object"""
        runner_threads = [ThreadExecutor(test_launcher.run) for test_launcher in self.test_launchers]

        RunQATests.LOGGER.info(f"Launching {len(runner_threads)} tests...")

        for runner_thread in runner_threads:
            runner_thread.start()

        RunQATests.LOGGER.info(f'Waiting until tests finish...')

        for runner_thread in runner_threads:
            runner_thread.join()

        RunQATests.LOGGER.info(f'Tests have been finished...')