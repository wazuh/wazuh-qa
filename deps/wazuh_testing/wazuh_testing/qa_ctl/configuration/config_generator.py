import os
import random

from tempfile import gettempdir
from sys import exit
from packaging.version import parse

from wazuh_testing.tools import file
from wazuh_testing.tools.exceptions import QAValueError
from wazuh_testing.tools.time import get_current_timestamp
from wazuh_testing.qa_ctl import QACTL_LOGGER
from wazuh_testing.tools.logging import Logging
from wazuh_testing.tools.s3_package import get_s3_package_url
from wazuh_testing.qa_ctl.provisioning.wazuh_deployment.wazuh_s3_package import WazuhS3Package
from wazuh_testing.tools.github_repository import get_last_wazuh_version
from wazuh_testing.qa_ctl.provisioning.local_actions import run_local_command


class QACTLConfigGenerator:
    """Class implemented with te purpose of generating the configuration fields needed in a YAML
    configuration file of the QACTL tool. In order to get te configuration file generated automatically,
    we use the info given by the documentation of the tests that are going to be executed. Plus, there can
    be also a wazuh version parameter that indicates which version of wazuh the user wants to install.

    Args:
        tests (list): list with all the test that the user desires to run.
        wazuh_version (string): version of the wazuh packages that the user desires to install.
        This parameter is set to None by default. In case that version parameter is not given, the
        wazuh package version will be taken from the documetation test information

    Attributes:
        tests (list): list with all the test that the user desires to run.
        wazuh_version (string): version of the wazuh packages that the user desires to install.
        This parameter is set to None by default. In case that version parameter is not given, the
        wazuh package version will be taken from the documetation test information
        qactl_used_ips_file (string): string with the full path where the file containing the used IPs
        is located.
        config_file_path (string): string with the full path where the YAML configuration file will be
        generated.
    """

    BOX_MAPPING = {
        'ubuntu': 'qactl/ubuntu_20_04',
        'centos': 'qactl/centos_8'
    }

    BOX_INFO = {
        'qactl/ubuntu_20_04': {
            'connection_method': 'ssh',
            'user': 'vagrant',
            'password': 'vagrant',
            'connection_port': 22,
            'ansible_python_interpreter': '/usr/bin/python3',
            'system': 'deb',
            'installation_files_path': '/tmp'
        },
        'qactl/centos_8': {
            'connection_method': 'ssh',
            'user': 'vagrant',
            'password': 'vagrant',
            'connection_port': 22,
            'ansible_python_interpreter': '/usr/bin/python3',
            'system': 'rpm',
            'installation_files_path': '/tmp'
        }
    }

    LOGGER = Logging.get_logger(QACTL_LOGGER)

    def __init__(self, tests, wazuh_version, qa_files_path=f"{gettempdir()}/wazuh-qa"):
        self.tests = tests
        self.wazuh_version = get_last_wazuh_version() if wazuh_version is None else wazuh_version
        self.qactl_used_ips_file = f"{gettempdir()}/qactl_used_ips.txt"
        self.config_file_path = f"{gettempdir()}/config_{get_current_timestamp()}.yaml"
        self.config = {}
        self.hosts = []
        self.qa_files_path = qa_files_path

    def __get_qa_branch(self):
        return f"{self.wazuh_version.split('.')[0]}.{self.wazuh_version.split('.')[1]}".replace('v', '')

    def __get_test_info(self, test_name):
        """Get information from a documented test.

        Args:
            test_name (string): string containing the name of the test.

        Returns:
            dict : return the info of the named test in dict format.
        """
        qa_docs_command = f"qa-docs -T {test_name} -o {gettempdir()} -I {self.qa_files_path}/tests"

        run_local_command(qa_docs_command)

        # Read test data file
        try:
            info = file.read_json_file(f"{gettempdir()}/{test_name}.json")
        except FileNotFoundError:
            raise QAValueError(f"Could not find {gettempdir()}/{test_name}.json file. Perhaps qa-docs has not "
                               f"generated it correctly. Try manually with command: {qa_docs_command}",
                               QACTLConfigGenerator.LOGGER.error)

        # Add test name extra info
        info['test_name'] = test_name

        # Delete test data file
        file.delete_file(f"{gettempdir()}/{test_name}.json")

        return info

    def __get_all_tests_info(self):
        """Get the info of the documentation of all the test that are going to be run.

        Returns:
            dict object : dict containing all the information of the tests given from their documentation.
        """
        tests_info = [self.__get_test_info(test) for test in self.tests]

        return tests_info

    def __validate_test_info(self, test_info, user_input=True, log_error=True):
        """Validate the test information in order to check that the fields that contains are suitable
        for trying to generate a configuration data.

        Args:
            test_info (dict): dict containing all the info of the test. This info is by its containing documentation
            user_input (boolean): boolean that checks if there is going to be an input from the user.
            This parameter is set to True by default.
            log_error (boolean): boolean that checks if there is going to be a logging of the errors.
            This parameter is set to True by default.

        Returns:
            boolean : True if the validation has succeed, False otherwise
        """
        def _ask_user_input():
            """Ask if the user desires to continue with the current instance execution"""
            user_continue = input('Do you want to continue with qa-ctl running? [y/n]: ')
            if user_continue.lower() != 'y':
                QACTLConfigGenerator.LOGGER.debug('The user has decided to stop execution due to incompatibility '
                                                  'between test and qa-ctl')
                exit(0)

        def _validation_error(log_error=True, error_message=None, user_input=True):
            """Show the possible validation error and check if the user wants to continue with the execution even if the
            validation has failed.

            Agrs:
                user_input (boolean): boolean that checks if there is going to be an input from the user.
                This parameter is set to True by default.
                error_message (string): string containing the error message. This parameter is set to None by default.
                log_error (boolean): boolean that checks if there is going to be a logging of the errors.
                This parameter is set to True by default.
            """
            if log_error:
                QACTLConfigGenerator.LOGGER.error(error_message)
            if user_input:
                _ask_user_input()

        def _check_validate(check, test_info, allowed_values, user_input, log_error):
            """Check if the validation process for a field has succeed.

            Args:
                check (string) : item that is going to be validated.
                test_info (dict) : test info data to validate.
                allowed_values (dict): dict containing all the allowed values for the item.
                user_input (boolean): boolean that checks if there is going to be an input from the user.
                log_error (boolean): boolean that checks if there is going to be a logging of the errors.

            Returns:
                boolean : True in case the validation checking has succeed, false otherwise.
            """
            # Intersection of allowed values and test info values
            if len(list(set(test_info[check]) & set(allowed_values))) == 0:
                error_message = f"{test_info['test_name']} cannot be launched. Reason: Currently we do not "\
                                f"support {test_info[check]}. Allowed values: {allowed_values}"
                _validation_error(log_error, error_message, user_input)

                return False

            return True

        allowed_info = {
            'test_system': ['linux'],
            'test_vendor': ['centos', 'ubuntu']
        }

        validation_ok = True

        # Validate checks
        for check, allowed_values in allowed_info.items():
            validation_ok = _check_validate(check, test_info, allowed_values, user_input, log_error)
            if not validation_ok:
                return False

        # Validate version requirements
        if parse(str(test_info['test_wazuh_min_version'])) > parse(str(self.wazuh_version)):
            error_message = f"The minimal version of wazuh to launch the {test_info['test_name']} is " \
                            f"{test_info['test_wazuh_min_version']} and you are using {self.wazuh_version}"
            _validation_error(log_error, error_message, user_input)

            return False

        return True

    def __get_host_IP(self):
        """Get an unused ip dinamically and in the range of 10.150.50.x. The ip is generated automatically
        by checking in the IPs used file which IPs are already being used in order to avoid re-using them.

        Returns:
            str: string containing an unused IP."""
        HOST_NETWORK = '10.150.50.x'

        def ip_is_already_used(ip, qactl_host_used_ips):
            with open(qactl_host_used_ips) as used_ips_file:
                lines = used_ips_file.readlines()

                for line in lines:
                    if ip in line:
                        return True

            return False

        if not os.path.exists(self.qactl_used_ips_file):
            open(self.qactl_used_ips_file, 'a').close()

        # Get a free IP in HOST_NETWORK range
        for _ip in range(1, 256):
            host_ip = HOST_NETWORK.replace('x', str(_ip))
            if not ip_is_already_used(host_ip, self.qactl_used_ips_file):
                break
            if _ip == 255:
                raise QAValueError(f"Could not find an IP available in {HOST_NETWORK}",
                                   QACTLConfigGenerator.LOGGER.error)

        # Write new used IP in used IPs file
        with open(self.qactl_used_ips_file, 'a') as used_ips_file:
            used_ips_file.write(f"{host_ip}\n")

        return host_ip

    def __delete_ip_entry(self, host_ip):
        """Delete an IP entry in the file that contains all the IPs that are currently being used.

        Args:
            host_ip (string): contains the ip that is going to be deleted from the used IPs file.
        """
        data = file.read_file(self.qactl_used_ips_file)

        data = data.replace(f"{host_ip}\n", '')

        file.write_file(self.qactl_used_ips_file, data)

    def __add_instance(self, test_vendor, test_name, test_target, test_system, vm_cpu=1, vm_memory=1024):
        """Add a new provider instance for the deployment module. T

        Args:
            test_vendor (string): name of the vendor of the vagrant box.
            test_name (string): contains the name of the test that is going to be run.
            test_target (string): contains the target of the test.
            test_system (string): The system in where the test needs to be run.
            vm_cpu (int): number of CPUs that will be dedicated to the new vagrant box.
            This parameter is set to 1 by default.
            vm_memory (int): size of the ram that will be dedicated to the new vagrant box.

        Returns:
            dict object: dict containing all the field required for generating a new vagrant box in the deployment
                         module.
        """
        instance_ip = self.__get_host_IP()
        instance = {
            'enabled': True,
            'vagrantfile_path': gettempdir(),
            'vagrant_box': QACTLConfigGenerator.BOX_MAPPING[test_vendor],
            'vm_memory': vm_memory,
            'vm_cpu': vm_cpu,
            'vm_name': f"{test_target}_{test_name}",
            'vm_system': test_system,
            'label': f"{test_target}_{test_name}",
            'vm_ip': instance_ip
        }
        self.hosts.append(instance_ip)

        return instance

    def __get_package_url(self, instance):
        """Get the url of the package that needs to be installed.

        Args:
            instance (dict): dict object with all the information needed to generate the url of the package.

        Returns:
            package_url (string): String with the URL of the package.
        """
        target = 'manager' if 'manager' in self.config['deployment'][instance]['provider']['vagrant']['label'] \
            else 'agent'
        vagrant_box = self.config['deployment'][instance]['provider']['vagrant']['vagrant_box']
        system = QACTLConfigGenerator.BOX_INFO[vagrant_box]['system']
        architecture = WazuhS3Package.get_architecture(system)

        package_url = get_s3_package_url('live', target, self.wazuh_version, '1', system, architecture)

        return package_url

    def __process_deployment_data(self, tests_info):
        """Generate the data for the deployment module with the information of the tests given as parameter.

        Args:
            test_info(dict object): dict object containing information of all the tests that are going to be run.
        """
        self.config['deployment'] = {}

        for test in tests_info:
            if self.__validate_test_info(test):
                # Choose items from the available list. To be improved in future versions
                if 'ubuntu' in test['test_vendor'] and 'centos' in test['test_vendor']:
                    vendors = ['ubuntu', 'centos']
                    test['test_vendor'] = random.choice(vendors)
                else:
                    test['test_vendor'] = 'ubuntu' if 'ubuntu' in test['test_vendor'] else 'centos'

                test['test_target'] = 'manager' if 'manager' in test['test_target'] else 'agent'
                test['test_system'] = 'linux'

                # Process deployment data
                host_number = len(self.config['deployment'].keys()) + 1
                vm_name = f"{test['test_name']}_{get_current_timestamp()}"
                self.config['deployment'][f"host_{host_number}"] = {
                    'provider': {
                        'vagrant': self.__add_instance(test['test_vendor'], vm_name, test['test_target'],
                                                       test['test_system'])
                    }
                }
                # Add manager if the target is an agent
                if test['test_target'] == 'agent':
                    host_number += 1
                    self.config['deployment'][f"host_{host_number}"] = {
                        'provider': {
                            'vagrant': self.__add_instance(test['test_vendor'], vm_name, 'manager',
                                                           test['test_system'])
                        }
                    }

    def __process_provision_data(self):
        """Generate the data for the provision module using the fields from the already generated deployment module."""
        self.config['provision'] = {'hosts': {}}

        for instance in self.config['deployment'].keys():
            self.config['provision']['hosts'][instance] = {'host_info': {}, 'wazuh_deployment': {}, 'qa_framework': {}}

            # Host info
            vm_ip = self.config['deployment'][instance]['provider']['vagrant']['vm_ip']
            vm_box = self.config['deployment'][instance]['provider']['vagrant']['vagrant_box']
            self.config['provision']['hosts'][instance]['host_info'] = dict(QACTLConfigGenerator.BOX_INFO[vm_box])
            self.config['provision']['hosts'][instance]['host_info']['host'] = vm_ip

            # Wazuh deployment
            target = 'manager' if 'manager' in self.config['deployment'][instance]['provider']['vagrant']['label'] \
                else 'agent'
            s3_package_url = self.__get_package_url(instance)
            self.config['provision']['hosts'][instance]['wazuh_deployment'] = {
                'type': 'package',
                'target': target,
                's3_package_url': s3_package_url,
                'installation_files_path': QACTLConfigGenerator.BOX_INFO[vm_box]['installation_files_path'],
                'health_check': True
            }
            if target == 'agent':
                # Add manager IP to the agent. The manager's host will always be the one after the agent's host.
                manager_host_number = int(instance.replace('host_', '')) + 1
                self.config['provision']['hosts'][instance]['wazuh_deployment']['manager_ip'] = \
                    self.config['deployment'][f"host_{manager_host_number}"]['provider']['vagrant']['vm_ip']

            # QA framework
            wazuh_qa_branch = self.__get_qa_branch()
            self.config['provision']['hosts'][instance]['qa_framework'] = {
                'wazuh_qa_branch': wazuh_qa_branch,
                'qa_workdir': gettempdir()
            }

    def __process_test_data(self, tests_info):
        """Generate the data for the test module with the information of the tests given as parameter.

        Args:
            test_info(dict object): dict object containing information of all the tests that are going to be run.
        """
        self.config['tests'] = {}
        test_host_number = len(self.config['tests'].keys()) + 1

        for test in tests_info:
            instance = f"host_{test_host_number}"
            self.config['tests'][instance] = {'host_info': {}, 'test': {}}
            self.config['tests'][instance]['host_info'] = \
                dict(self.config['provision']['hosts'][instance]['host_info'])
            self.config['tests'][instance]['test'] = {
                'type': 'pytest',
                'path': {
                    'test_files_path': f"{gettempdir()}/wazuh-qa/{test['test_path']}",
                    'run_tests_dir_path': f"{gettempdir()}/wazuh-qa/test/integration",
                    'test_results_path': f"{gettempdir()}/test_{test['test_name']}_{get_current_timestamp()}/"
                }
            }
            test_host_number += 1
            # If it is an agent test then we skip the next manager instance since no test will be launched in that
            # instance
            if test['test_target'] == 'agent':
                test_host_number += 1

    def __process_test_info(self, tests_info):
        """Process all the info of the desired tests that are going to be run in order to generate the data
           configuration for the YAML config file.

        Args:
            tests_info(dict object): dict object containing information of all the tests that are going to be run.
        """
        self.__process_deployment_data(tests_info)
        self.__process_provision_data()
        self.__process_test_data(tests_info)

    def run(self):
        """Run an instance with the parameters created. This generates the YAML configuration file automatically."""
        info = self.__get_all_tests_info()
        self.__process_test_info(info)
        file.write_yaml_file(self.config_file_path, self.config)

    def destroy(self):
        """Destroy the instance created by deleting its ip entry in the used IPs file and its configuration file."""
        for host_ip in self.hosts:
            self.__delete_ip_entry(host_ip)

        file.delete_file(self.config_file_path)
