import os
import sys
from tempfile import gettempdir

from wazuh_testing.qa_ctl.provisioning.ansible import read_ansible_instance, remove_known_host
from wazuh_testing.qa_ctl.provisioning.ansible.ansible_inventory import AnsibleInventory
from wazuh_testing.qa_ctl.run_tests.test_launcher import TestLauncher
from wazuh_testing.qa_ctl.run_tests.pytest import Pytest
from wazuh_testing.tools.thread_executor import ThreadExecutor
from wazuh_testing.qa_ctl import QACTL_LOGGER
from wazuh_testing.tools.logging import Logging
from wazuh_testing.tools.time import get_current_timestamp
from wazuh_testing.tools import file
from wazuh_testing.qa_ctl.provisioning.local_actions import qa_ctl_docker_run


class QATestRunner():
    """The class encapsulates the build of the tests from the test parameters read from the configuration file

        Args:
            test_parameters (dict): a dictionary containing all the required data to build the tests
            qa_ctl_configuration (QACTLConfiguration): QACTL configuration.

        Attributes:
            inventory_file_path (string): Path of the inventory file generated.
            test_launchers (list(TestLauncher)): Test launchers objects (one for each host).
            qa_ctl_configuration (QACTLConfiguration): QACTL configuration.
            test_parameters (dict): a dictionary containing all the required data to build the tests
    """
    LOGGER = Logging.get_logger(QACTL_LOGGER)

    def __init__(self, tests_parameters, qa_ctl_configuration):
        self.inventory_file_path = None
        self.test_launchers = []
        self.test_parameters = tests_parameters
        self.qa_ctl_configuration = qa_ctl_configuration

        self.__process_inventory_data(tests_parameters)
        self.__process_test_data(tests_parameters)

    def __process_inventory_data(self, instances_info):
        """Process config file info to generate the ansible inventory file.

         Args:
            instances_info (dict): Dictionary with hosts configuration.
        """
        QATestRunner.LOGGER.debug('Processing inventory data from testing hosts info')
        instances_list = []

        for _, host_value in instances_info.items():
            for module_key, module_value in host_value.items():
                if module_key == 'host_info':
                    current_host = module_value['host']

                    # Remove the host IP from known host file to avoid the SSH key fingerprint error
                    remove_known_host(current_host, QATestRunner.LOGGER)

                    if current_host:
                        instances_list.append(read_ansible_instance(module_value))

        inventory_instance = AnsibleInventory(ansible_instances=instances_list)
        self.inventory_file_path = inventory_instance.inventory_file_path
        QATestRunner.LOGGER.debug('Inventory data from testing hosts info was processed successfully')

    def __process_test_data(self, instances_info):
        """Process test data configuration and build the test launchers, setting the related class attribute.

        Args:
            instances_info (dict): Dictionary with hosts configuration.
        """
        QATestRunner.LOGGER.debug('Processing testing data from hosts')

        for _, host_value in instances_info.items():
            test_launcher = TestLauncher([], self.inventory_file_path, self.qa_ctl_configuration)
            for module_key, module_value in host_value.items():
                hosts = host_value['host_info']['host']
                ansible_admin_user = host_value['host_info']['ansible_admin_user'] if 'ansible_admin_user' \
                    in host_value['host_info'] else None
                if module_key == 'test':
                    test_launcher.add(self.__build_test(module_value, hosts, ansible_admin_user))
            self.test_launchers.append(test_launcher)
        QATestRunner.LOGGER.debug('Testing data from hosts info was processed successfully')

    def __build_test(self, test_params, host=['all'], ansible_admin_user=None):
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
            test_dict['qa_ctl_configuration'] = self.qa_ctl_configuration

            if 'path' in test_params:
                paths = test_params['path']
                test_dict['tests_path'] = paths['test_files_path']
                test_dict['tests_result_path'] = paths['test_results_path']
                test_dict['tests_run_dir'] = paths['run_tests_dir_path']

            test_dict['component'] = test_params['component'] if 'component' in test_params else None
            test_dict['modules'] = test_params['modules'] if 'modules' in test_params else None
            test_dict['system'] = test_params['system'] if 'system' in test_params else None
            test_dict['wazuh_install_path'] = test_params['wazuh_install_path'] if 'wazuh_install_path' in test_params \
                else None
            test_dict['ansible_admin_user'] = ansible_admin_user

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
                    test_dict['verbose_level'] = False if 'verbose_level' not in parameters else \
                        parameters['verbose_level']
                    test_dict['log_level'] = None if 'log_level' not in parameters else parameters['log_level']
                    test_dict['markers'] = [] if 'markers' not in parameters else parameters['markers']

            return Pytest(**test_dict)
        else:
            raise ValueError(f"Test \'{test_params['type']}\' is not allowed. Allowed value: pytest")

    def run(self):
        """Run testing threads. One thread per TestLauncher object"""
        # If Windows, then run a Linux docker container to run testing stage with qa-ctl testing
        if sys.platform == 'win32':
            tmp_config_file_name = f"config_{get_current_timestamp()}.yaml"
            tmp_config_file = os.path.join(gettempdir(), 'wazuh_qa_ctl', tmp_config_file_name)

            # Save original directory where to store the results in Windows host
            original_result_paths = [self.test_parameters[host_key]['test']['path']['test_results_path']
                                     for host_key, _ in self.test_parameters.items()]

            # Change the destination directory, as the results will initially be stored in the shared volume between
            # the Windows host and the docker container (Windows tmp as /wazuh_qa_ctl).
            test_results_folder = f"test_results_{get_current_timestamp()}"
            temp_test_results_files_path = f"/wazuh_qa_ctl/{test_results_folder}"

            index = 0
            for host_key, _ in self.test_parameters.items():
                self.test_parameters[host_key]['test']['path']['test_results_path'] = \
                    f"{temp_test_results_files_path}_{index}"
                index += 1

            # Write a custom configuration file with only running test section
            file.write_yaml_file(tmp_config_file, {'tests': self.test_parameters})

            try:
                qa_ctl_docker_run(tmp_config_file_name, self.qa_ctl_configuration.qa_ctl_launcher_branch,
                                  self.qa_ctl_configuration.debug_level, topic='launching the tests')
                # Move all test results to their original paths specified in Windows qa-ctl configuration
                index = 0
                for _, host_data in self.test_parameters.items():
                    source_directory = os.path.join(gettempdir(), 'wazuh_qa_ctl', f"{test_results_folder}_{index}")
                    file.move_everything_from_one_directory_to_another(source_directory,  original_result_paths[index])
                    file.delete_path_recursively(source_directory)
                    QATestRunner.LOGGER.info(f"The results of {host_data['test']['path']['test_files_path']} tests "
                                             f"have been saved in {original_result_paths[index]}")
                    index += 1
            finally:
                file.remove_file(tmp_config_file)
        else:
            runner_threads = [ThreadExecutor(test_launcher.run) for test_launcher in self.test_launchers]

            QATestRunner.LOGGER.info(f"Launching {len(runner_threads)} tests")

            for runner_thread in runner_threads:
                runner_thread.start()

            QATestRunner.LOGGER.info('Waiting for tests to finish')

            for runner_thread in runner_threads:
                runner_thread.join()

            QATestRunner.LOGGER.info('The test run is finished')

            for _, host_data in self.test_parameters.items():
                if 'RUNNING_ON_DOCKER_CONTAINER' not in os.environ:
                    QATestRunner.LOGGER.info(f"The results of {host_data['test']['path']['test_files_path']} tests "
                                             f"have been saved in {host_data['test']['path']['test_results_path']}")

    def destroy(self):
        """"Destroy all the temporary files created during a running QAtestRunner instance"""
        if os.path.exists(self.inventory_file_path) and sys.platform != 'win32':
            os.remove(self.inventory_file_path)
