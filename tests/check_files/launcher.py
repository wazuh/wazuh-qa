import argparse
import os
import sys
from tempfile import gettempdir

from wazuh_testing.qa_ctl.configuration.config_instance import ConfigInstance
from wazuh_testing.qa_ctl.configuration.config_generator import QACTLConfigGenerator
from wazuh_testing.qa_ctl.provisioning.ansible.playbook_generator import PlaybookGenerator
from wazuh_testing.tools.s3_package import get_production_package_url, get_last_production_package_url
from wazuh_testing.tools.time import get_current_timestamp
from wazuh_testing.tools import file
from wazuh_testing.qa_ctl.provisioning import local_actions
from wazuh_testing.tools import github_checks
from wazuh_testing.tools.logging import Logging
from wazuh_testing.tools.exceptions import QAValueError
from wazuh_testing.qa_ctl import QACTL_LOGGER
from wazuh_testing.tools.github_api_requests import WAZUH_QA_REPO

TMP_FILES = os.path.join(gettempdir(), 'wazuh_check_files')
WAZUH_QA_FILES = os.path.join(TMP_FILES, 'wazuh-qa')
CHECK_FILES_TEST_PATH = os.path.join(WAZUH_QA_FILES, 'tests', 'check_files')
CHECK_FILES_PLAYBOOKS_PATH = os.path.join(CHECK_FILES_TEST_PATH, 'playbooks')
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

logger = Logging(QACTL_LOGGER)


def get_parameters():
    """
    Returns:
        argparse.Namespace: Object with the user parameters.
    """
    parser = argparse.ArgumentParser()

    parser.add_argument('--action', '-a', type=str, action='store', required=False, dest='test_action',
                        choices=['install', 'upgrade', 'uninstall'], default='install',
                        help='Wazuh action to be carried out to check the check-files')

    parser.add_argument('--os', '-o', type=str, action='store', required=False, dest='os_system',
                        choices=['centos7', 'centos8', 'ubuntu'], default='ubuntu')

    parser.add_argument('--version', '-v', type=str, action='store', required=False, dest='wazuh_version',
                        help='Wazuh installation and tests version.')

    parser.add_argument('--debug', '-d', action='count', default=0, help='Run in debug mode. You can increase the debug'
                                                                         ' level with more [-d+]')

    parser.add_argument('--qa-branch', type=str, action='store', required=False, dest='qa_branch', default='master',
                        help='Set a custom wazuh-qa branch to download and run the tests files')

    parser.add_argument('--target', '-t', type=str, action='store', required=False, dest='wazuh_target',
                        choices=['manager', 'agent'], default='manager', help='Wazuh test target. manager or agent')

    parser.add_argument('--no-validation', action='store_true', help='Disable the script parameters validation.')

    arguments = parser.parse_args()

    return arguments


def set_environment(parameters):
    """Prepare the local environment for the test run.

    Args:
        parameters (argparse.Namespace): Object with the user parameters.

    """
    set_logger(parameters)

    # Download wazuh-qa repository to launch the check-files test files.
    local_actions.download_local_wazuh_qa_repository(branch=parameters.qa_branch, path=TMP_FILES)


def set_logger(parameters):
    """Set the test logging.

    Args:
        parameters (argparse.Namespace): Object with the user parameters.
    """
    level = 'DEBUG' if parameters.debug >= 1 else 'INFO'
    logger.set_level(level)

    # Disable traceback if it is not run in DEBUG mode
    if level != 'DEBUG':
        sys.tracebacklimit = 0


def validate_parameters(parameters):
    """Validate input script parameters.

    Raises:
        QAValueError: If a script parameters has a invalid value.
    """
    logger.info('Validating input parameters')

    # Check if QA branch exists
    if not github_checks.branch_exists(parameters.qa_branch, repository=WAZUH_QA_REPO):
        raise QAValueError(f"{parameters.qa_branch} branch does not exist in Wazuh QA repository.",
                           logger.error, QACTL_LOGGER)

    # Check version parameter
    if parameters.wazuh_version and len((parameters.wazuh_version).split('.')) != 3:
        raise QAValueError(f"Version parameter has to be in format x.y.z. You entered {parameters.wazuh_version}",
                           logger.error, QACTL_LOGGER)

    # Check if Wazuh has the specified version
    if parameters.wazuh_version and not github_checks.version_is_released(parameters.wazuh_version):
        raise QAValueError(f"The wazuh {parameters.wazuh_version} version has not been released. Enter a right "
                           'version.', logger.error, QACTL_LOGGER)
    logger.info('Input parameters validation has passed successfully')


def generate_qa_ctl_configuration(parameters, playbooks_path, qa_ctl_config_generator):
    """Generate the qa-ctl configuration according to the script parameters and write it into a file.

    Args:
        parameters (argparse.Namespace): Object with the user parameters.
        playbook_path (list(str)): List with the playbooks path to run with qa-ctl
        qa_ctl_config_generator (QACTLConfigGenerator): qa-ctl config generator object.

    Returns:
        str: Configuration file path where the qa-ctl configuration has been saved.
    """

    logger.info('Generating qa-ctl configuration')

    current_timestamp = str(get_current_timestamp()).replace('.', '_')
    config_file_path = os.path.join(TMP_FILES, f"check_files_config_{current_timestamp}.yaml")
    os_system = parameters.os_system

    instance_name = f"check_files_{os_system}_{current_timestamp}"
    instance = ConfigInstance(instance_name, os_system)

    # Generate deployment configuration
    deployment_configuration = qa_ctl_config_generator.get_deployment_configuration([instance])

    # Generate tasks configuration data
    tasks_configuration = qa_ctl_config_generator.get_tasks_configuration([instance], playbooks_path)

    # Generate qa-ctl configuration file
    qa_ctl_configuration = {**deployment_configuration, **tasks_configuration}
    file.write_yaml_file(config_file_path, qa_ctl_configuration)

    logger.info(f"The qa-ctl configuration has been created successfully in {config_file_path}")

    return config_file_path


def generate_test_playbooks(test_action, os_system, wazuh_target, wazuh_version, qa_branch, local_checkfiles_data_path,
                            debug):
    """Generate the necessary playbooks to run the test.

    Args:
        test_action (str): Test action [install, upgrade, uninstall...]
        os_system (str): Operating system where the test will be launched.
        wazuh_target (str): Wazuh target, manager or agent.
        wazuh_version (str): Wazuh version to install and test.
    """
    playbooks_path = []
    package_url = get_production_package_url(wazuh_target, os_system, wazuh_version) if wazuh_version else \
        get_last_production_package_url(wazuh_target, os_system)
    package_name = os.path.split(package_url)[1]

    check_files_too_url = f"https://raw.githubusercontent.com/wazuh/wazuh-qa/{qa_branch}/deps/" \
                          'wazuh_testing/wazuh_testing/scripts/check_files.py'
    check_files_tool_destination = '/var/ossec/check_files.py'
    ignore_check_files_path = ['/sys', '/proc', '/run', '/var/ossec']
    check_files_extra_args = '' if debug == 0 else ('-d' if debug == 1 else '-dd')
    check_files_data_output_path = '/post_check_files_data.json'
    check_files_command = f"sudo python3 {check_files_tool_destination} -p / -i {' '.join(ignore_check_files_path)} " \
                          f"-o {check_files_data_output_path} {check_files_extra_args}"

    if test_action == 'install':
        # Install Wazuh on remote host
        playbooks_path.append(PlaybookGenerator.install_wazuh(package_name=package_name, package_url=package_url,
                                                              package_destination='/tmp', os_system=os_system,
                                                              os_platform='linux'))
        # Download the check-files tool in the remote host
        playbooks_path.append(PlaybookGenerator.download_files({check_files_too_url: check_files_tool_destination},
                                                               playbook_parameters={'become': True}))
        # Run the check-files tool
        playbooks_path.append(PlaybookGenerator.run_linux_commands([check_files_command],
                                                                   playbook_parameters={'become': True}))
        # Get the check-files result data
        playbooks_path.append(
            PlaybookGenerator.fetch_files({check_files_data_output_path: local_checkfiles_data_path},
                                          playbook_parameters={'become': True})
        )

    elif test_action == 'upgrade':
        playbooks_path.append(PlaybookGenerator.install_wazuh(package_name=package_name, package_url=package_url,
                                                              package_destination='/tmp', os_system=os_system,
                                                              os_platform='linux'))
        playbooks_path.append(PlaybookGenerator.upgrade_wazuh(package_name=package_name, package_url=package_url,
                                                              package_destination='/tmp', os_system=os_system,
                                                              os_platform='linux'))
        # Run the check-files tool
        playbooks_path.append(PlaybookGenerator.run_linux_commands([check_files_command]))
        # Get the check-files result data
        playbooks_path.append(
            PlaybookGenerator.fetch_files({check_files_data_output_path: local_checkfiles_data_path})
        )

    elif test_action == 'uninstall':
        # Install Wazuh on remote host
        playbooks_path.append(PlaybookGenerator.install_wazuh(package_name=package_name, package_url=package_url,
                                                              package_destination='/tmp', os_system=os_system,
                                                              os_platform='linux'))
        # Uninstall Wazuh on remote host
        playbooks_path.append(PlaybookGenerator.uninstall_wazuh(os_system=os_system, os_platform='linux'))
        # Run the check-files tool
        playbooks_path.append(PlaybookGenerator.run_linux_commands([check_files_command]))
        # Get the check-files result data
        playbooks_path.append(
            PlaybookGenerator.fetch_files({check_files_data_output_path: local_checkfiles_data_path})
        )

    return playbooks_path


def main():
    """Run the check-files test according to the script parameters."""
    parameters = get_parameters()
    qa_ctl_config_generator = QACTLConfigGenerator()
    current_timestamp = str(get_current_timestamp()).replace('.', '_')
    post_check_files_data_path = os.path.join(TMP_FILES, f"post_check_files_data_{current_timestamp}.yaml")

    # Set logging and Download QA files
    set_environment(parameters)

    # Validate script parameters
    if not parameters.no_validation:
        validate_parameters(parameters)

    # Generate the test playbooks to run with qa-ctl
    playbooks_path = generate_test_playbooks(parameters.test_action, parameters.os_system, parameters.wazuh_target,
                                             parameters.wazuh_version, parameters.qa_branch, post_check_files_data_path,
                                             parameters.debug)

    # Generate the qa-ctl configuration
    qa_ctl_config_file_path = generate_qa_ctl_configuration(parameters, playbooks_path, qa_ctl_config_generator)

    # Run the qa-ctl with the generated configuration. Launch deployment + custom playbooks.
    qa_ctl_extra_args = '' if parameters.debug == 0 else ('-d' if parameters.debug == 1 else '-dd')
    local_actions.run_local_command_printing_output(f"qa-ctl -c {qa_ctl_config_file_path} {qa_ctl_extra_args} "
                                                    '--no-validation-logging')

    # # Get check-files data
    # baseline_file_path = os.path.join(TMP_FILES, 'wazuh_qa_ctl', f"baseline_{arguments.os_system}_"
    #                                                              f"{current_timestamp}.json")
    # latest_check_files_path = os.path.join(TMP_FILES, 'wazuh_qa_ctl', f"latest_{arguments.os_system}_"
    #                                                                   f"{current_timestamp}.json")

    # # Launch the check-files pytest
    # pytest_launcher = 'python -m pytest' if sys.platform == 'win32' else 'python3 -m pytest'
    # pytest_command = f"cd {CHECK_FILES_TEST_PATH} && {pytest_launcher} test_system_check_files --before-file " \
    #                  f"{baseline_file_path} --after-file {latest_check_files_path}"
    # test_result = local_actions.run_local_command_returning_output(pytest_command)


if __name__ == '__main__':
    main()
