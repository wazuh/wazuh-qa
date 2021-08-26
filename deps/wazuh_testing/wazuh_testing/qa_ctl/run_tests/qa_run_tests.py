from wazuh_testing.qa_ctl.provisioning.ansible.ansible_instance import AnsibleInstance
from wazuh_testing.qa_ctl.provisioning.ansible.ansible_inventory import AnsibleInventory
from wazuh_testing.qa_ctl.run_tests.pytest import Pytest


class RunQATests():
    """The class encapsulates the build of the tests from the test parameters read from the configuration file

        Args:
            test_parameters (dict): a dictionary containing all the required data to build the tests

        Attributes:
            tests (list(Pytest)): list of Pytest instances to run at the specified remote machines
            inventory_file_path (string): Path of the inventory file generated.
    """

    def __init__(self, tests_parameters):
        self.tests = []
        self.inventory_file_path = None

        self.__process_inventory_data(tests_parameters)

        for _, host_value in tests_parameters.items():
            self.tests.append(self.__build_test(host_value['test'], host_value['host_info']['host']))

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
        """Process config file info to generate the ansible inventory file."""
        instances_list = []

        for _, host_value in instances_info.items():
            for module_key, module_value in host_value.items():
                if module_key == 'host_info':
                    current_host = module_value['host']
                    if current_host:
                        instances_list.append(self.__read_ansible_instance(module_value))

        inventory_instance = AnsibleInventory(ansible_instances=instances_list)
        self.inventory_file_path = inventory_instance.inventory_file_path

    def __build_test(self, test_params, host=['all']):
        """Private method in charge of reading all the required fields to build one test of type Pytest

            Args:
                test_params (dict): all the data regarding one specific test
                host: Host IP where the test will be run

            Returns:
                Pytest: one instance of Pytest built from the parameters in test_params
        """
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
