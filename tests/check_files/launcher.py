import argparse
import os
import yaml
from tempfile import gettempdir

from wazuh_testing.qa_ctl.configuration.config_instance import ConfigInstance
from wazuh_testing.qa_ctl.configuration.config_generator import QACTLConfigGenerator
from wazuh_testing.tools.time import get_current_timestamp
from wazuh_testing.tools import file
from wazuh_testing.qa_ctl.provisioning import local_actions


TMP_FILES = os.path.join(gettempdir(), 'wazuh_qa_ctl')
WAZUH_QA_FILES = os.path.join(TMP_FILES, 'wazuh-qa')
CHECK_FILES_PLAYBOOKS_PATH = os.path.join(WAZUH_QA_FILES, 'tests', 'check_files', 'playbooks')
INSTALL_PLAYBOOK_PATH = os.path.join(CHECK_FILES_PLAYBOOKS_PATH, 'install_wazuh.yaml')
UPGRADE_PLAYBOOK_PATH = os.path.join(CHECK_FILES_PLAYBOOKS_PATH, 'upgrade_wazuh.yaml')
UNINSTALL_PLAYBOOOK_PATH = os.path.join(CHECK_FILES_PLAYBOOKS_PATH, 'uninstall_wazuh.yaml')
CHECK_FILES_PLAYBOOOK_PATH = os.path.join(CHECK_FILES_PLAYBOOKS_PATH, 'run_check_files_tool.yaml')
FETCH_FILES_PLAYBOOOK_PATH = os.path.join(CHECK_FILES_PLAYBOOKS_PATH, 'fetch_files.yaml')

ACTION_MAPPING = {
    'install': [INSTALL_PLAYBOOK_PATH, CHECK_FILES_PLAYBOOOK_PATH, FETCH_FILES_PLAYBOOOK_PATH],
    'upgrade': [INSTALL_PLAYBOOK_PATH, UPGRADE_PLAYBOOK_PATH, CHECK_FILES_PLAYBOOOK_PATH, FETCH_FILES_PLAYBOOOK_PATH],
    'uninstall': [INSTALL_PLAYBOOK_PATH, CHECK_FILES_PLAYBOOOK_PATH, FETCH_FILES_PLAYBOOOK_PATH]
}


def get_script_parameters():
    parser = argparse.ArgumentParser()

    parser.add_argument('--action', '-a', type=str, action='store', required=False, dest='test_action',
                        choices=['install', 'upgrade', 'uninstall'], default='install',
                        help='Wazuh action to be carried out to check the check-files')

    parser.add_argument('--os', '-o', type=str, action='store', required=False, nargs='+', dest='operating_systems',
                        choices=['centos', 'ubuntu'], default=['ubuntu'],
                        help='System/s where the tests will be launched.')

    parser.add_argument('--version', '-v', type=str, action='store', required=False, dest='version',
                        help='Wazuh installation and tests version.')

    parser.add_argument('--debug', '-d', action='count', default=0, help='Run in debug mode. You can increase the debug'
                                                                         ' level with more [-d+]')

    parser.add_argument('--qa-branch', type=str, action='store', required=False, dest='qa_branch', default='master',
                        help='Set a custom wazuh-qa branch to download and run the tests files')

    arguments = parser.parse_args()

    return arguments


def generate_qa_ctl_configuration(script_parameters, qa_ctl_configuration):
    instances = []
    config_file_path = os.path.join(TMP_FILES, f"check_files_config_{get_current_timestamp()}.yaml")

    # Get instances objects. One for each test operating system
    for operating_system in script_parameters.operating_systems:
        instance_name = f"check_files_{operating_system}_{get_current_timestamp()}".replace('.', '_')
        instances.append(ConfigInstance(instance_name, operating_system))

    # Generate deployment configuration
    deployment_configuration = qa_ctl_configuration.get_deployment_configuration(instances)

    # Download wazuh-qa repository to launch the check-files test files.
    local_actions.download_local_wazuh_qa_repository(branch=script_parameters.qa_branch,
                                                     path=os.path.join(gettempdir(), 'wazuh_qa_ctl'))

    # Get the necessary playbooks to run according to the test action
    playbooks_path = ACTION_MAPPING[script_parameters.test_action]

    # Generate tasks configuration data
    tasks_configuration = qa_ctl_configuration.get_tasks_configuration(instances, playbooks_path)

    # Generate qa-ctl configuration file
    qa_ctl_configuration = {**deployment_configuration, **tasks_configuration}
    file.write_yaml_file(config_file_path, qa_ctl_configuration)

    return config_file_path


def main():
    arguments = get_script_parameters()
    qa_ctl_configuration = QACTLConfigGenerator()

    qa_ctl_config_file_path = generate_qa_ctl_configuration(arguments, qa_ctl_configuration)

    print(qa_ctl_config_file_path)



if __name__ == '__main__':
    main()
