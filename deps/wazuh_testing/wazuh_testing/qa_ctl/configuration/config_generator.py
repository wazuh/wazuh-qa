from tempfile import gettempdir

from wazuh_testing.tools.file import write_json_file, read_json_file, delete_file


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
        self.config = {}

    def __qa_docs_mocking(self, test_name):
        file = f"{gettempdir()}/mocked_data.json"
        mocking_data = {
            'test_path': 'tests/integration/test_vulnerability_detector/test_general_settings/test_general_settings_enabled.py',
            'test_wazuh_min_version': '4.2.0',
            'test_system': 'linux',
            'test_vendor': 'ubuntu',
            'test_os_version': '20.04',
            'test_target': 'manager'
        }

        write_json_file(file, mocking_data)

    def __get_test_info(self, test_name):
        self.__qa_docs_mocking(test_name)
        info = read_json_file(f"{gettempdir()}/mocked_data.json")
        info['test_name'] = test_name
        delete_file(f"{gettempdir()}/mocked_data.json")
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


    def __add_instance(self, test_vendor, test_name, test_target, test_system, vm_cpu=1, vm_memory=1024):
        import random
        instance = {
            'enabled': True,
            'vagrantfile_path': gettempdir(),
            'vagrant_box': QACTLConfigGenerator.BOX_MAPPING[test_vendor],
            'vm_memory': vm_memory,
            'vm_cpu': vm_cpu,
            'vm_name': f"{test_target}_{test_name}",
            'vm_system': test_system,
            'label': f"{test_target}_{test_name}",
            'vm_ip': f"172.16.1.7{random.randint(0,9)}"
        }

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
