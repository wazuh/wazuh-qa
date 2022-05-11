import sys
import re
import copy
from os.path import join, exists
from tempfile import gettempdir
from packaging.version import parse
from copy import deepcopy

from wazuh_testing.tools import file
from wazuh_testing.tools.exceptions import QAValueError
from wazuh_testing.tools.time import get_current_timestamp
from wazuh_testing.qa_ctl import QACTL_LOGGER
from wazuh_testing.tools.logging import Logging
from wazuh_testing.tools.s3_package import get_s3_package_url
from wazuh_testing.qa_ctl.provisioning.wazuh_deployment.wazuh_s3_package import WazuhS3Package
from wazuh_testing.qa_ctl.provisioning.local_actions import run_local_command_returning_output


class QACTLConfigGenerator:
    """Class implemented with te purpose of generating the configuration fields needed in a YAML
    configuration file of the QACTL tool. In order to get te configuration file generated automatically,
    we use the info given by the documentation of the tests that are going to be executed. Plus, there can
    be also a wazuh version parameter that indicates which version of wazuh the user wants to install.

    Args:
        tests (list): list with all the test that the user desires to run.
        wazuh_version (string): version of the wazuh packages that the user desires to install.
        systems (list(str)): Systems with which the tests will be launched
        This parameter is set to None by default. In case that version parameter is not given, the
        wazuh package version will be taken from the documetation test information

    Attributes:
        test_modules_data (dict): dict with all the tests that the user desires to run.
        wazuh_version (string): version of the wazuh packages that the user desires to install.
        This parameter is set to None by default. In case that version parameter is not given, the
        wazuh package version will be taken from the documetation test information
        qactl_used_ips_file (string): string with the full path where the file containing the used IPs
        is located.
        config_file_path (string): string with the full path where the YAML configuration file will be
        generated.
    """

    LOGGER = Logging.get_logger(QACTL_LOGGER)
    LINUX_TMP = '/tmp'
    WINDOWS_TMP = 'C:\\Users\\vagrant\\AppData\\Local\\Temp'
    WINDOWS_DEFAULT_WAZUH_INSTALL_PATH = 'C:\\Program Files (x86)\\ossec-agent'
    LINUX_DEFAULT_WAZUH_INSTALL_PATH = '/var/ossec'

    BOX_MAPPING = {
        'CentOS 7': 'qactl/centos_7',
        'CentOS 8': 'qactl/centos_8',
        'Ubuntu Focal': 'qactl/ubuntu_20_04',
        'Windows Server 2019': 'qactl/windows_2019'
    }

    SYSTEMS = {
        'centos_7': {
            'os_version': 'CentOS 7',
            'os_platform': 'linux'
        },
        'centos_8': {
            'os_version': 'CentOS 8',
            'os_platform': 'linux'
        },
        'ubuntu_focal': {
            'os_version': 'Ubuntu Focal',
            'os_platform': 'linux'
        },
        'windows_2019': {
            'os_version': 'Windows Server 2019',
            'os_platform': 'windows'
        }
    }

    DEFAULT_BOX_RESOURCES = {
        'qactl/centos_7': {
            'cpu': 1,
            'memory': 1024
        },
        'qactl/centos_8': {
            'cpu': 1,
            'memory': 1024
        },
        'qactl/ubuntu_20_04': {
            'cpu': 1,
            'memory': 1024
        },
        'qactl/windows_2019': {
            'cpu': 2,
            'memory': 2048
        }
    }

    BOX_INFO = {
        'qactl/ubuntu_20_04': {
            'ansible_connection': 'ssh',
            'ansible_user': 'vagrant',
            'ansible_password': 'vagrant',
            'ansible_port': 22,
            'ansible_python_interpreter': '/usr/bin/python3',
            'system': 'deb',
            'installation_files_path': LINUX_TMP
        },
        'qactl/centos_7': {
            'ansible_connection': 'ssh',
            'ansible_user': 'vagrant',
            'ansible_password': 'vagrant',
            'ansible_port': 22,
            'ansible_python_interpreter': '/usr/bin/python',
            'system': 'rpm',
            'installation_files_path': LINUX_TMP
        },
        'qactl/centos_8': {
            'ansible_connection': 'ssh',
            'ansible_user': 'vagrant',
            'ansible_password': 'vagrant',
            'ansible_port': 22,
            'ansible_python_interpreter': '/usr/bin/python3',
            'system': 'rpm',
            'installation_files_path': LINUX_TMP
        },
        'qactl/windows_2019': {
            'ansible_connection': 'winrm',
            'ansible_user': 'vagrant',
            'ansible_password': 'vagrant',
            'ansible_port': 5985,
            'ansible_winrm_server_cert_validation': 'ignore',
            'system': 'windows',
            'ansible_admin_user': 'vagrant',
            'ansible_python_interpreter': 'C:\\Users\\vagrant\\AppData\\Local\\Programs\\Python\\Python39\\python.exe',
            'installation_files_path': WINDOWS_TMP
        }
    }

    def __init__(self, test_modules_data=None, wazuh_version=None, qa_branch='master',
                 qa_files_path=join(gettempdir(), 'wazuh_qa_ctl', 'wazuh-qa'), systems=None):
        self.test_modules_data = test_modules_data
        self.wazuh_version = wazuh_version
        self.systems = systems
        self.qactl_used_ips_file = join(gettempdir(), 'wazuh_qa_ctl', 'qactl_used_ips.txt')
        self.config_file_path = join(gettempdir(), 'wazuh_qa_ctl', f"config_{get_current_timestamp()}.yaml")
        self.config = {}
        self.hosts = []
        self.qa_branch = qa_branch
        self.qa_files_path = qa_files_path

        # Create qa-ctl temporarily files path
        file.recursive_directory_creation(join(gettempdir(), 'wazuh_qa_ctl'))

    def __get_module_info(self, type, component, suite, module):
        """Get information from a documented test.

        Args:
            test_name (string): string containing the name of the test.

        Returns:
            dict : return the info of the named test in dict format.
        """
        suite_command = f"-s {suite}" if suite else ''
        qa_docs_command = f"qa-docs -p {join(self.qa_files_path, 'tests')} -o {join(gettempdir(), 'wazuh_qa_ctl')} " \
                          f"-t {type} -c {component} {suite_command} -m {module} --no-logging"
        test_data_file_path = f"{join(gettempdir(), 'wazuh_qa_ctl', 'output', module)}.json"

        run_local_command_returning_output(qa_docs_command)

        # Read test data file
        try:
            info = file.read_json_file(test_data_file_path)
        except FileNotFoundError:
            raise QAValueError(f"Could not find {test_data_file_path} file. Perhaps qa-docs has not "
                               f"generated it correctly. Try manually with command: {qa_docs_command}",
                               QACTLConfigGenerator.LOGGER.error, QACTL_LOGGER)

        # Add test name extra info
        info['test_name'] = module

        # Delete test data file
        file.delete_file(test_data_file_path)

        return info

    def __get_all_tests_info(self):
        """Get the info of the documentation of all the test that are going to be run.

        Returns:
            dict object : dict containing all the information of the tests given from their documentation.
        """
        tests_info = []
        if self.test_modules_data['suites']:
            for type, component, suite, module in zip(self.test_modules_data['types'],
                                                      self.test_modules_data['components'],
                                                      self.test_modules_data['suites'],
                                                      self.test_modules_data['modules']):
                tests_info.append(self.__get_module_info(type, component, suite, module))
        else:
            for type, component, module in zip(self.test_modules_data['types'], self.test_modules_data['components'],
                                               self.test_modules_data['modules']):
                tests_info.append(self.__get_module_info(type, component, '', module))

        return tests_info

    def __validate_test_info(self, test_info):
        """Validate the test information in order to check that the fields that contains are suitable
        for trying to generate a configuration data.

        Args:
            test_info (dict): dict containing all the info of the test. This info is by its containing documentation
            user_input (boolean): boolean that checks if there is going to be an input from the user.

        Returns:
            boolean : True if the validation has succeed, False otherwise
        """
        def _check_validate(check, test_info, allowed_values):
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
                raise QAValueError(error_message, QACTLConfigGenerator.LOGGER.error, QACTL_LOGGER)

            return True

        allowed_info = {
            'os_platform': ['linux', 'windows'],
            'os_version': list(QACTLConfigGenerator.BOX_MAPPING.keys())
        }

        # Validate checks
        for check, allowed_values in allowed_info.items():
            _check_validate(check, test_info, allowed_values)

        # Validate version requirements
        if parse(str(test_info['tests'][0]['wazuh_min_version'])) > parse(str(self.wazuh_version)):
            error_message = f"The minimal version of wazuh to launch the {test_info['test_name']} is " \
                            f"{test_info['tests'][0]['wazuh_min_version']} and you are using {self.wazuh_version}"
            raise QAValueError(error_message, QACTLConfigGenerator.LOGGER.error, QACTL_LOGGER)

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

        if not exists(self.qactl_used_ips_file):
            open(self.qactl_used_ips_file, 'a').close()

        # Get a free IP in HOST_NETWORK range
        for _ip in range(2, 256):
            host_ip = HOST_NETWORK.replace('x', str(_ip))
            if not ip_is_already_used(host_ip, self.qactl_used_ips_file):
                break
            if _ip == 255:
                raise QAValueError(f"Could not find an IP available in {HOST_NETWORK}",
                                   QACTLConfigGenerator.LOGGER.error, QACTL_LOGGER)

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

    def __add_instance(self, os_version, test_name, test_target, os_platform):
        """Add a new provider instance for the deployment module. T

        Args:
            os_version (string): name of the vendor of the vagrant box.
            test_name (string): contains the name of the test that is going to be run.
            test_target (string): contains the target of the test.
            os_platform (string): The system in where the test needs to be run.
            vm_cpu (int): number of CPUs that will be dedicated to the new vagrant box.
            This parameter is set to 1 by default.
            vm_memory (int): size of the ram that will be dedicated to the new vagrant box.

        Returns:
            dict object: dict containing all the field required for generating a new vagrant box in the deployment
                         module.
        """
        vm_cpu = 1
        vm_memory = 1024

        if os_version in self.BOX_MAPPING:
            box = self.BOX_MAPPING[os_version]
            vm_cpu = self.DEFAULT_BOX_RESOURCES[box]['cpu']
            vm_memory = self.DEFAULT_BOX_RESOURCES[box]['memory']

        instance_ip = self.__get_host_IP()
        instance = {
            'enabled': True,
            'vagrantfile_path': join(gettempdir(), 'wazuh_qa_ctl'),
            'vagrant_box': QACTLConfigGenerator.BOX_MAPPING[os_version],
            'vm_memory': vm_memory,
            'vm_cpu': vm_cpu,
            'vm_name': f"{test_target}_{test_name}",
            'vm_system': os_platform,
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

    def __add_deployment_config_block(self, test_name, os_version, targets, os_platform):
        """Add a configuration block to deploy a test environment in qa-ctl.

        Args:
            test_name (string): Test name.
            os_version (string): Host vendor to deploy (e.g: CentOS 8).
            targets (string): Test target (manager or agent).
            os_platform (string): host system (e.g: linux).
        """
        # Process deployment data
        host_number = len(self.config['deployment'].keys()) + 1
        vm_name = f"{test_name}_{get_current_timestamp()}".replace('.', '_')
        self.config['deployment'][f"host_{host_number}"] = {
            'provider': {
                'vagrant': self.__add_instance(os_version, vm_name, targets, os_platform)
            }
        }
        # Add manager if the target is an agent
        if targets == 'agent':
            host_number += 1
            self.config['deployment'][f"host_{host_number}"] = {
                'provider': {
                    'vagrant': self.__add_instance('CentOS 8', vm_name, 'manager', 'linux')
                }
            }

    def __process_deployment_data(self, tests_info):
        """Generate the data for the deployment module with the information of the tests given as parameter.

        Args:
            test_info(dict object): dict object containing information of all the tests that are going to be run.

        Raises:
            QAValueError: If the test system or specified systems are not valid.
        """
        self.config['deployment'] = {}

        # If not system parameter was specified, then one is automatically selected
        if not self.systems:
            for test in tests_info:
                if self.__validate_test_info(test):
                    os_version = ''
                    if 'CentOS 8' in test['os_version']:
                        os_version = 'CentOS 8'
                    elif 'Ubuntu Focal' in test['os_version']:
                        os_version = 'Ubuntu Focal'
                    elif 'CentOS 7' in test['os_version']:
                        os_version = 'CentOS 7'
                    elif 'Windows Server 2019' in test['os_version']:
                        os_version = 'Windows Server 2019'
                    else:
                        raise QAValueError(f"No valid system was found for {test['name']} test",
                                           QACTLConfigGenerator.LOGGER.error, QACTL_LOGGER)

                    targets = 'manager' if 'manager' in test['targets'] else 'agent'
                    os_platform = 'windows' if 'Windows' in os_version else 'linux'

                    self.__add_deployment_config_block(test['test_name'], os_version, targets, os_platform)

        # If system parameter is specified and have values
        elif isinstance(self.systems, list) and len(self.systems) > 0:
            for system in self.systems:
                for test in tests_info:
                    if self.__validate_test_info(test):
                        version = self.SYSTEMS[system]['os_version']
                        platform = self.SYSTEMS[system]['os_platform']
                        targets = 'manager' if 'manager' in test['targets'] and platform == 'linux' else 'agent'

                        self.__add_deployment_config_block(test['test_name'], version, targets, platform)
        else:
            raise QAValueError('Unable to process systems in the automatically generated configuration',
                               QACTLConfigGenerator.LOGGER.error, QACTL_LOGGER)

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
            installation_files_path = QACTLConfigGenerator.BOX_INFO[vm_box]['installation_files_path']
            system = QACTLConfigGenerator.BOX_INFO[vm_box]['system']
            wazuh_install_path = self.WINDOWS_DEFAULT_WAZUH_INSTALL_PATH if system == 'windows' else \
                self.LINUX_DEFAULT_WAZUH_INSTALL_PATH

            self.config['provision']['hosts'][instance]['wazuh_deployment'] = {
                'type': 'package',
                'target': target,
                's3_package_url': s3_package_url,
                'installation_files_path': installation_files_path,
                'health_check': True,
                'wazuh_install_path': wazuh_install_path
            }

            if target == 'agent':
                # Add manager IP to the agent. The manager's host will always be the one after the agent's host.
                manager_host_number = int(instance.replace('host_', '')) + 1
                self.config['provision']['hosts'][instance]['wazuh_deployment']['manager_ip'] = \
                    self.config['deployment'][f"host_{manager_host_number}"]['provider']['vagrant']['vm_ip']

            # QA framework
            self.config['provision']['hosts'][instance]['qa_framework'] = {
                'wazuh_qa_branch': self.qa_branch,
                'qa_workdir': file.join_path([installation_files_path, 'wazuh_qa_ctl'], system)
            }

    def __add_testing_config_block(self, instance, installation_files_path, system, test_path, test_name, modules,
                                   component):
        """Add a configuration block to launch a test in qa-ctl.

        Args:
            instance (str): block instance name (host_x).
            installation_files_path (str): Path where locate wazuh qa-ctl files.
            system (str): System where launch the test.
            test_path (str): Path where are located the test files.
            test_name (str): Test name.
            modules (list(str)): List of modules.
            component (str): Test component (manager, agent).
        """
        self.config['tests'][instance] = {'host_info': {}, 'test': {}}
        self.config['tests'][instance]['host_info'] = \
            dict(self.config['provision']['hosts'][instance]['host_info'])
        wazuh_install_path = self.WINDOWS_DEFAULT_WAZUH_INSTALL_PATH if system == 'windows' else \
            self.LINUX_DEFAULT_WAZUH_INSTALL_PATH

        self.config['tests'][instance]['test'] = {
            'type': 'pytest',
            'path': {
                'test_files_path': file.join_path([installation_files_path, 'wazuh_qa_ctl', 'wazuh-qa',
                                                   test_path], system),
                'run_tests_dir_path': file.join_path([installation_files_path, 'wazuh_qa_ctl', 'wazuh-qa',
                                                      'tests', 'integration'], system),
                'test_results_path': join(gettempdir(), 'wazuh_qa_ctl', f"{test_name}_{get_current_timestamp()}")
            },
            'wazuh_install_path': wazuh_install_path,
            'system': system,
            'component': component,
            'modules':  modules
        }

    def __set_testing_config(self, tests_info):
        """Add all blocks corresponding to the testing configuration for qa-ctl

        Args:
            test_info(dict object): dict object containing information of all the tests that are going to be run.
        """
        # Calculate the host that will run the test

        # If there is no test config block, then start in host_+1
        if len(self.config['tests'].keys()) == 0:
            test_host_number = len(self.config['tests'].keys()) + 1
        else:
            last_config_test_item = len(self.config['tests'].keys())
            instance = f"host_{last_config_test_item}"
            # If the last test was for manager, then move on to the next one.
            if self.config['tests'][instance]['test']['component'] == 'manager':
                test_host_number = len(self.config['tests'].keys()) + 1
            # If the last test was for agent, then 1 host must be skipped, since it is the manager for an agent test.
            else:
                test_host_number = len(self.config['tests'].keys()) + 2

        for test in tests_info:
            instance = f"host_{test_host_number}"
            vm_box = self.config['deployment'][instance]['provider']['vagrant']['vagrant_box']
            installation_files_path = QACTLConfigGenerator.BOX_INFO[vm_box]['installation_files_path']
            system = QACTLConfigGenerator.BOX_INFO[vm_box]['system']

            system = 'linux' if system == 'deb' or system == 'rpm' else system
            modules = copy.deepcopy(test['components'])
            component = self.config['provision']['hosts'][instance]['wazuh_deployment']['target']
            # Cut out the full path, and convert it to relative path (tests/integration....)
            test_path = re.sub(r".*wazuh-qa.*(tests.*)", r"\1", test['path'])
            # Convert test path string to the corresponding according to the system
            test_path = file.join_path([test_path], system)

            self.__add_testing_config_block(instance, installation_files_path, system, test_path,
                                            test['test_name'], modules, component)
            test_host_number += 1
            # If it is an agent test then we skip the next manager instance since no test will be launched in that
            # instance
            if component == 'agent':
                test_host_number += 1

    def __process_test_data(self, tests_info):
        """Generate the data for the test module with the information of the tests given as parameter.

        Args:
            test_info(dict object): dict object containing information of all the tests that are going to be run.

        Raises:
            QAValueError: If the specified systems are not valid.
        """
        self.config['tests'] = {}

        if not self.systems:
            self.__set_testing_config(tests_info)
        # If we want to launch the test in one or multiple systems specified in qa-ctl parameters
        elif isinstance(self.systems, list) and len(self.systems) > 0:
            for _ in self.systems:
                self.__set_testing_config(tests_info)
        else:
            raise QAValueError('Unable to process systems in the automatically generated configuration',
                               QACTLConfigGenerator.LOGGER.error, QACTL_LOGGER)

    def __process_test_info(self, tests_info):
        """Process all the info of the desired tests that are going to be run in order to generate the data
           configuration for the YAML config file.

        Args:
            tests_info(dict object): dict object containing information of all the tests that are going to be run.
        """
        self.__process_deployment_data(tests_info)
        self.__process_provision_data()
        self.__process_test_data(tests_info)

    def __proces_config_info(self):
        """Write the config section info in the qa-ctl configuration file"""
        # It is only necessary to specify the qa_ctl_launcher_branch when using qa-ctl on Windows, as this branch will
        # be used to launch qa-ctl in the docker container used for provisioning and testing.
        if sys.platform == 'win32':
            self.config['config'] = {}
            self.config['config']['qa_ctl_launcher_branch'] = self.qa_branch

    def run(self):
        """Run an instance with the parameters created. This generates the YAML configuration file automatically."""
        info = self.__get_all_tests_info()
        self.__process_test_info(info)
        self.__proces_config_info()
        file.write_yaml_file(self.config_file_path, self.config)

    def destroy(self):
        """Destroy the instance created by deleting its ip entry in the used IPs file and its configuration file."""
        for host_ip in self.hosts:
            self.__delete_ip_entry(host_ip)

        file.delete_file(self.config_file_path)

    def get_deployment_configuration(self, instances):
        """Generate the qa-ctl configuration required for the deployment of the specified config-instances.

        Args:
            instances(list(ConfigInstance)): List of config-instances to deploy.

        Returns:
            dict: Configuration block corresponding to the deployment of the instances

        Raises:
            QAValueError: If the instance operating system is not allowed for generating the qa-ctl configuration.
        """
        deployment_configuration = {'deployment': {}}

        for index, instance in enumerate(instances):
            try:
                box = self.BOX_MAPPING[instance.os_version]
            except KeyError as exception:
                raise QAValueError(f"Could not find a qa-ctl box for {instance.os_version}",
                                   QACTLConfigGenerator.LOGGER.error, QACTL_LOGGER) from exception

            instance_ip = self.__get_host_IP()
            # Assign the IP to the instance object (Needed later to generate host config data)
            instance.ip = instance_ip

            deployment_configuration['deployment'][f"host_{index + 1}"] = {
                'provider': {
                    'vagrant': {
                        'enabled': True,
                        'vagrantfile_path': join(gettempdir(), 'wazuh_qa_ctl'),
                        'vagrant_box': box,
                        'vm_memory': instance.memory,
                        'vm_cpu': instance.cpu,
                        'vm_name': instance.name,
                        'vm_system': instance.os_platform,
                        'label': instance.name,
                        'vm_ip': instance_ip
                    }
                }
            }

        return deployment_configuration

    def get_tasks_configuration(self, playbook_info, instances=None, playbook_type='local', remote_hosts_info=None):
        """Generate the qa-ctl configuration required for running ansible tasks.

        Args:
            instances (list(ConfigInstance)): List of config-instances to deploy.
            playbook_info (dict): Playbook dictionary info. {playbook_name: playbook_path}
            playbook_type (str): Playbook path configuration [local or remote_url].
            remote_hosts_info (list(dict)): List with all the information of the remote hosts.

        Returns:
            dict: Configuration block corresponding to the ansible tasks to run with qa-ctl.
        """
        def get_tasks_configuration(host_info, playbook_info, playbook_type):
            playbooks_dict = [{'name': playbook_name, 'local_path': playbook_path} if playbook_type == 'local' else
                              {'name': playbook_name, 'remote_url': playbook_path} for playbook_name, playbook_path
                              in playbook_info.items()]
            return {
                'host_info': host_info,
                'playbooks': playbooks_dict
            }

        tasks_configuration = {'tasks': {}}

        if instances:  # Build task configuration for local instances host
            for index, instance in enumerate(instances):
                instance_box = self.BOX_MAPPING[instance.os_version]
                host_info = QACTLConfigGenerator.BOX_INFO[instance_box]
                host_info['host'] = instance.ip
                tasks_configuration['tasks'][f"task_{index + 1}"] = get_tasks_configuration(host_info, playbook_info,
                                                                                            playbook_type)
        elif remote_hosts_info:  # Build task configuration for remote AWS hosts
            for index, custom_host_info in enumerate(remote_hosts_info):
                host_info = deepcopy(custom_host_info)
                tasks_configuration['tasks'][f"task_{index + 1}"] = get_tasks_configuration(host_info, playbook_info,
                                                                                            playbook_type)
        return tasks_configuration
