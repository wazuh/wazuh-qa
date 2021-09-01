import random
import os

from tempfile import gettempdir

from wazuh_testing.tools import file
from wazuh_testing.tools.exceptions import QAValueError


class QACTLConfigGenerator:

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
            'ansible_python_interpreter': '/usr/bin/python3'
        },
        'qactl/centos_8': {
            'connection_method': 'ssh',
            'user': 'vagrant',
            'password': 'vagrant',
            'connection_port': 22,
            'ansible_python_interpreter': '/usr/bin/python3'
        }
    }

    def __init__(self, tests):
        self.tests = tests
        self.qactl_used_ips_file = f"{gettempdir()}/qactl_used_ips.txt"
        self.config = {}
        self.hosts = []

    def __qa_docs_mocking(self, test_name):
        mocked_file = f"{gettempdir()}/mocked_data.json"
        mocking_data = {
            'test_path': 'tests/integration/test_vulnerability_detector/test_general_settings/test_general_settings_enabled.py',
            'test_wazuh_min_version': '4.2.0',
            'test_system': 'linux',
            'test_vendor': 'ubuntu',
            'test_os_version': '20.04',
            'test_target': 'manager'
        }

        file.write_json_file(mocked_file, mocking_data)

    def __get_test_info(self, test_name):
        self.__qa_docs_mocking(test_name)
        info = file.read_json_file(f"{gettempdir()}/mocked_data.json")
        info['test_name'] = test_name
        file.delete_file(f"{gettempdir()}/mocked_data.json")
        return info

    def __get_all_tests_info(self):
        #tests_info = [ __get_test_info(test) for test in self.tests ]
        tests_info = [
            {
                'test_path': 'tests/integration/test_vulnerability_detector/test_general_settings/test_general_settings_enabled.py',
                'test_wazuh_min_version': '4.2.0',
                'test_system': 'linux',
                'test_vendor': 'ubuntu',
                'test_os_version': '20.04',
                'test_target': 'manager',
                'test_name': 'test_general_settings_enabled'
            },
            {
                'test_path': 'tests/integration/test_vulnerability_detector/test_general_settings/test_general_settings_enabled.py',
                'test_wazuh_min_version': '4.2.0',
                'test_system': 'linux',
                'test_vendor': 'centos',
                'test_os_version': '8',
                'test_target': 'agent',
                'test_name': 'test_general_settings_enabled'
            },
            {
                'test_path': 'tests/integration/test_vulnerability_detector/test_general_settings/test_general_settings_enabled.py',
                'test_wazuh_min_version': '4.2.0',
                'test_system': 'linux',
                'test_vendor': 'ubuntu',
                'test_os_version': '20.04',
                'test_target': 'manager',
                'test_name': 'test_general_settings_enabled'
            }
        ]
        return tests_info


    def __validate_test_info(self, test_info):
        pass

    def __get_host_IP(self):
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
                raise QAValueError(f"Could not find an IP available in {HOST_NETWORK}")

        # Write new used IP in used IPs file
        with open(self.qactl_used_ips_file, 'a') as used_ips_file:
            used_ips_file.write(f"{host_ip}\n")

        return host_ip

    def __delete_ip_entry(self, host_ip):
        data = file.read_file(self.qactl_used_ips_file)

        data = data.replace(f"{host_ip}\n", '')

        file.write_file(self.qactl_used_ips_file, data)

    def __add_instance(self, test_vendor, test_name, test_target, test_system, vm_cpu=1, vm_memory=1024):
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

    def __process_deployment_data(self, tests_info):
        self.config['deployment'] = {}

        for test in tests_info:
            self.__validate_test_info(test)

            # Process deployment data
            host_number = len(self.config['deployment'].keys()) + 1
            self.config['deployment'][f"host_{host_number}"] = {
                'provider': {
                   'vagrant': self.__add_instance(test['test_vendor'], test['test_name'], test['test_target'],
                                                  test['test_system'])
                }
            }
            # Add manager if the target is an agent
            if test['test_target'] == 'agent':
                host_number += 1
                self.config['deployment'][f"host_{host_number}"] = {
                    'provider': {
                        'vagrant': self.__add_instance(test['test_vendor'], test['test_name'], 'manager',
                                                       test['test_system'])
                    }
                }

    def __process_provision_data(self):
        self.config['provision'] = {'hosts': {}}

        for instance in self.config['deployment'].keys():
            self.config['provision']['hosts'][instance] = {'host_info': {}, 'wazuh_deployment': {}, 'qa_framework': {}}

            # Host info
            vm_ip = self.config['deployment'][instance]['provider']['vagrant']['vm_ip']
            vm_box = self.config['deployment'][instance]['provider']['vagrant']['vagrant_box']
            self.config['provision']['hosts'][instance]['host_info'] = dict(QACTLConfigGenerator.BOX_INFO[vm_box])
            self.config['provision']['hosts'][instance]['host_info']['host'] = vm_ip

            # Wazuh deployment
            s3_package_url = 'mocked_url'
            target = 'manager' if 'manager' in self.config['deployment'][instance]['provider']['vagrant']['label'] \
                else 'agent'
            self.config['provision']['hosts'][instance]['wazuh_deployment'] = {
                'type': 'package',
                'target': target,
                's3_package_url': s3_package_url,
                'health_check': True
            }
            if target == 'agent':
                # Add manager IP to the agent. The manager's host will always be the one after the agent's host.
                manager_host_number = int(instance.replace('host_', '')) + 1
                self.config['provision']['hosts'][instance]['wazuh_deployment']['manager_ip'] = \
                    self.config['deployment'][f"host_{manager_host_number}"]['provider']['vagrant']['vm_ip']

            # QA framework
            wazuh_qa_branch = 'mocked_branch'
            self.config['provision']['hosts'][instance]['qa_framework'] = {
                'wazuh_qa_branch': wazuh_qa_branch,
                'qa_workdir': gettempdir()
            }

    def __process_test_data(self, tests_info):
        self.config['tests'] = {}
        test_host_number = len(self.config['tests'].keys()) + 1

        for test in tests_info:
            instance = f"host_{test_host_number}"
            self.config['tests'][instance] = {'host_info': {}, 'test': {}}
            self.config['tests'][instance]['host_info'] = self.config['provision']['hosts'][instance]['host_info']
            self.config['tests'][instance]['test'] = {
                'type': 'pytest',
                'path': {
                    'test_files_path': f"{gettempdir()}/wazuh_qa/{test['test_path']}",
                    'run_tests_dir_path': f"{gettempdir()}/wazuh_qa/test/integration"
                }
            }
            test_host_number += 1
            # If it is an agent test then we skip the next manager instance since no test will be launched in that
            # instance
            if test['test_target'] == 'agent':
                test_host_number += 1

    def __process_test_info(self, tests_info):
        self.__process_deployment_data(tests_info)
        self.__process_provision_data()
        self.__process_test_data(tests_info)

        import json
        print(json.dumps(self.config, indent=4))

    def run(self):
        info = self.__get_all_tests_info()
        self.__process_test_info(info)

    def destroy(self):
        for host_ip in self.hosts:
            self.__delete_ip_entry(host_ip)
