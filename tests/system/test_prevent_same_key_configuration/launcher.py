# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2


import argparse
import os
import sys
from tempfile import gettempdir
import yaml
import json

from wazuh_testing.qa_ctl import QACTL_LOGGER
from wazuh_testing.qa_ctl.configuration.config_generator import QACTLConfigGenerator
from wazuh_testing.qa_ctl.provisioning import local_actions
from wazuh_testing.tools import file, github_checks
from wazuh_testing.tools.exceptions import QAValueError
from wazuh_testing.tools.github_api_requests import WAZUH_QA_REPO
from wazuh_testing.tools.logging import Logging
from wazuh_testing.tools.time import get_current_timestamp
from wazuh_testing.tools.s3_package import get_production_package_url, get_last_production_package_url, \
    get_s3_package_url
from wazuh_testing.qa_ctl.provisioning.ansible import playbook_generator
from wazuh_testing.qa_ctl.configuration.config_instance import ConfigInstance

TMP_FILES = os.path.join(gettempdir(), 'wazuh_prevent_same_key_config')
WAZUH_QA_FILES = os.path.join(TMP_FILES, 'wazuh-qa')
TEST_PREVENT_SAME_KEY_CONFIG_PATH = os.path.join(WAZUH_QA_FILES, 'tests', 'system')

logger = Logging(QACTL_LOGGER)
test_build_files = []


def get_parameters():
    """
    Returns:
        argparse.Namespace: Object with the user parameters.
    """
    parser = argparse.ArgumentParser()

    parser.add_argument('--os', '-o', type=str, action='store', required=False, dest='os_system',
                        choices=['centos_7', 'centos_8', 'ubuntu_focal'], default='centos_8')

    parser.add_argument('--auto-enrollment', '-a', action='store_true', dest='auto_enrollment',
                        help='Enable the agent enrollment.')

    parser.add_argument('--version', '-v', type=str, action='store', required=False, dest='wazuh_version',
                        help='Wazuh installation version.')

    parser.add_argument('--debug', '-d', action='count', default=0, help='Run in debug mode. You can increase the debug'
                                                                         ' level with more [-d+]')

    parser.add_argument('--persistent', '-p', action='store_true',
                        help='Persistent instance mode. Do not destroy the instances once the process has finished.')

    parser.add_argument('--qa-branch', type=str, action='store', required=False, dest='qa_branch', default='master',
                        help='Set a custom wazuh-qa branch to download and run the tests files')

    parser.add_argument('--output-file-path', type=str, action='store', required=False, dest='output_file_path',
                        help='Path to store all test results')

    arguments = parser.parse_args()

    return arguments


def set_environment(parameters, test_output_path=None):
    """Prepare the local environment for the test run.
    Args:
        parameters (argparse.Namespace): Object with the user parameters.
        test_output_path (str): Directory path where the tests result will be saved.
    """
    set_logger(parameters)

    local_actions.download_local_wazuh_qa_repository(branch=parameters.qa_branch, path=TMP_FILES)
    test_build_files.append(WAZUH_QA_FILES)

    if test_output_path is None:
        file.recursive_directory_creation(parameters.output_file_path)
    elif os.path.exists(test_output_path) and not os.path.isdir(test_output_path):
        raise ValueError(f"The given output path {test_output_path} already exists and is not a directory.")
    elif not os.path.exists(test_output_path):
        os.makedirs(test_output_path)


def set_logger(parameters):
    """Set the test logging.
    Args:
        parameters (argparse.Namespace): Object with the user parameters.
    """
    level = 'DEBUG' if parameters.debug >= 1 else 'INFO'
    logger.set_level(level)

    if level != 'DEBUG':
        sys.tracebacklimit = 0


def validate_parameters(parameters):
    """Validate input script parameters.
    Raises:
        QAValueError: If a script parameters has a invalid value.
    """
    logger.info('Validating input parameters')

    if not github_checks.branch_exists(parameters.qa_branch, repository=WAZUH_QA_REPO):
        raise QAValueError(f"{parameters.qa_branch} branch does not exist in Wazuh QA repository.",
                           logger.error, QACTL_LOGGER)

    if parameters.wazuh_version and len(parameters.wazuh_version.split('.')) != 3:
        raise QAValueError(f"Version parameter has to be in format x.y.z. You entered {parameters.wazuh_version}",
                           logger.error, QACTL_LOGGER)

    if parameters.wazuh_version and not github_checks.version_is_released(parameters.wazuh_version):
        raise QAValueError(f"The wazuh {parameters.wazuh_version} version has not been released. Enter a right "
                           'version.', logger.error, QACTL_LOGGER)

    logger.info('Input parameters validation has passed successfully')


def file_become_valid_json(file_path):
    with open(file_path, 'r+') as f:
        content = f.read()
        f.seek(0, 0)
        f.write('['.rstrip('\r\n') + '\n' + content)
    with open(file_path, 'a') as f:
        f.write(']')
    data = yaml.safe_load(open(file_path))
    content = json.dumps(data)
    with open(file_path, 'w') as f:
        f.write(content)


def generate_test_playbooks(parameters, qa_ctl_config_generator, local_client_keys_file_path,
                            local_log_output_file_path, local_agent_ctl_output_file_path
                            ):
    """Generate the necessary playbooks to run the test.
    Args:
        parameters (argparse.Namespace): Object with the user parameters.
        qa_ctl_config_generator (QACTLConfigGenerator): QACTLConfigGenerator object.
        local_client_keys_file_path (str): The path where the clients.keys file will be stored
        local_log_output_file_path (str): The path where the matched lines of the log will be stored.
        local_agent_ctl_output_file_path (str): The path where the output of the agent_control binary will be stored.
    Returns:
        list(dict): List of dictionaries with information of playbooks.
    """
    os_platform = 'linux'
    vm_package_destination = '/tmp'
    vm_log_output_path = '/tmp/log_output.txt'
    vm_agent_ctl_output_path = '/tmp/output_agent_control.json'
    vm_log_path = '/var/ossec/logs/ossec.log'
    vm_client_keys_file = '/var/ossec/etc/client.keys'
    save_log_command = fr'tail -n 10 {vm_log_path} > {vm_log_output_path}'
    save_control_output_command = f'c="$(/var/ossec/bin/agent_control -l -j)," ; echo $c >> {vm_agent_ctl_output_path}'
    manager_ip = qa_ctl_config_generator.get_host_ip()

    list_of_playbooks_info = []

    manager_package_url = get_s3_package_url('warehouse-test', 'manager', '4.4.0', 'duplicate.keys', 'rpm', 'x86_64')
    agent_package_url = get_s3_package_url('warehouse-test', 'agent', '4.4.0', 'duplicate.keys', 'rpm', 'x86_64')
    manager_package_name = os.path.split(manager_package_url)[1]
    agent_package_name = os.path.split(agent_package_url)[1]

    # manager_package_url = get_production_package_url('manager', parameters.os_system, parameters.wazuh_version) \
    #    if parameters.wazuh_version else get_last_production_package_url('manager', parameters.os_system)
    # agent_package_url = get_production_package_url('agent', parameters.os_system, parameters.wazuh_version) \
    #    if parameters.wazuh_version else get_last_production_package_url('agent', parameters.os_system)

    # Playbooks parameters

    install_manager_playbook_parameters = {
        'wazuh_target': 'manager', 'package_name': manager_package_name,
        'package_url': manager_package_url, 'package_destination': vm_package_destination,
        'os_system': parameters.os_system, 'os_platform': os_platform
    }

    configure_agent_disconnection_playbook_parameters = {
        'time': '15s',
        'playbook_parameters': {'become': True}
    }

    restart_manager_playbook_parameters = {
        'wazuh_target': 'manager',
        'playbook_parameters': {'become': True}
    }

    install_agent_1_playbooks_parameters = {
        'wazuh_target': 'agent', 'package_name': agent_package_name,
        'package_url': agent_package_url, 'package_destination': vm_package_destination,
        'os_system': parameters.os_system, 'os_platform': os_platform, 'manager_ip': manager_ip
    }

    install_agent_2_playbooks_parameters = {
        'wazuh_target': 'agent', 'package_name': agent_package_name,
        'package_url': agent_package_url, 'package_destination': vm_package_destination,
        'os_system': parameters.os_system, 'os_platform': os_platform, 'manager_ip': 'localhost'
    }

    fetch_client_keys_file_playbook_parameters = {
        'files_data': {vm_client_keys_file: local_client_keys_file_path},
        'playbook_parameters': {'become': True}
    }

    copy_client_keys_file_playbook_parameters = {
        'files_data': {local_client_keys_file_path: vm_client_keys_file},
        'playbook_parameters': {'become': True}
    }

    toggle_auto_enrollment_playbook_parameters = {
        'alternator': False if not parameters.auto_enrollment else True,
        'playbook_parameters': {'become': True}
    }

    configure_time_reconnect_playbook_parameters = {
        'time': 11,
        'playbook_parameters': {'become': True}
    }

    add_manager_ip_agent_2_playbook_parameters = {
        'manager_ip': manager_ip,
        'playbook_parameters': {'become': True}
    }

    restart_agent_2_playbook_parameters = {
        'wazuh_target': 'agent',
        'playbook_parameters': {'become': True}
    }

    save_log_playbook_parameters = {
        'commands': [save_log_command],
        'playbook_parameters': {'become': True}
    }

    fetch_log_output_file_playbook_parameters = {
        'files_data': {vm_log_output_path: local_log_output_file_path},
        'playbook_parameters': {'become': True}
    }

    stop_agent_playbook_parameters = {
        'wazuh_target': 'agent',
        'playbook_parameters': {'become': True}
    }

    start_agent_playbook_parameters = {
        'wazuh_target': 'agent',
        'playbook_parameters': {'become': True}
    }

    save_control_output_playbook_parameters = {
        'commands': [save_control_output_command],
        'playbook_parameters': {'become': True}
    }

    fetch_agent_ctl_output_playbook_parameters = {
        'files_data': {vm_agent_ctl_output_path: local_agent_ctl_output_file_path},
        'playbook_parameters': {'become': True}
    }

    # Playbooks generation

    list_of_playbooks_info.append({
        'install_manager': playbook_generator.install_wazuh(**install_manager_playbook_parameters),
        'configure_disconnection_time_manager': playbook_generator.configure_agent_disconnection_time(
            **configure_agent_disconnection_playbook_parameters),
        'restart_manager': playbook_generator.restart_wazuh(**restart_manager_playbook_parameters)
    })

    list_of_playbooks_info.append({
        'install_agent_1': playbook_generator.install_wazuh(**install_agent_1_playbooks_parameters)
    })

    list_of_playbooks_info.append({
        'install_agent_2': playbook_generator.install_wazuh(**install_agent_2_playbooks_parameters)
    })

    list_of_playbooks_info.append({
        'fetch_client_keys_file_agent_1': playbook_generator.fetch_files(**fetch_client_keys_file_playbook_parameters)
    })

    list_of_playbooks_info.append({
        'copy_client_keys_file_agent_2': playbook_generator.copy_files(**copy_client_keys_file_playbook_parameters),
        'configure_manager_ip_agent_2': playbook_generator.configure_manager_ip(
            **add_manager_ip_agent_2_playbook_parameters),
        'toggle_auto_enrollment_agent_2': playbook_generator.toggle_agent_enrollment(
            **toggle_auto_enrollment_playbook_parameters),
        'configure_time_reconnect': playbook_generator.configure_time_reconnect(
            **configure_time_reconnect_playbook_parameters),
        'restart_agent_2': playbook_generator.restart_wazuh(**restart_agent_2_playbook_parameters)
    })

    if not parameters.auto_enrollment:
        list_of_playbooks_info.append({
            'save_log_manager': playbook_generator.run_linux_commands(**save_log_playbook_parameters),
            'fetch_log_output_file_manager': playbook_generator.fetch_files(
                **fetch_log_output_file_playbook_parameters),
            'save_agent_ctl_output': playbook_generator.run_linux_commands(**save_control_output_playbook_parameters)
        })

        list_of_playbooks_info.append({
            'stop_agent_2': playbook_generator.stop_wazuh(**stop_agent_playbook_parameters)
        })

        list_of_playbooks_info.append({
            'stop_agent_1': playbook_generator.stop_wazuh(**stop_agent_playbook_parameters),
            'waiting_time': playbook_generator.wait_seconds(16)
        })

        list_of_playbooks_info.append({
            'save_agent_ctl_output': playbook_generator.run_linux_commands(**save_control_output_playbook_parameters)
        })

        list_of_playbooks_info.append({
            'start_agent_2': playbook_generator.start_wazuh(**start_agent_playbook_parameters)
        })

        list_of_playbooks_info.append({
            'waiting_time': playbook_generator.wait_seconds(16),
            'save_agent_ctl_output': playbook_generator.run_linux_commands(**save_control_output_playbook_parameters),
            'fetch_agent_ctl_output': playbook_generator.fetch_files(**fetch_agent_ctl_output_playbook_parameters)
        })
    else:
        list_of_playbooks_info.append({
            'waiting_time': playbook_generator.wait_seconds(75),
            'save_agent_ctl_output': playbook_generator.run_linux_commands(**save_control_output_playbook_parameters),
            'fetch_agent_ctl_output': playbook_generator.fetch_files(**fetch_agent_ctl_output_playbook_parameters)
        })

    qa_ctl_config_generator.delete_ip_entry(manager_ip)

    return list_of_playbooks_info


def generate_qa_ctl_configuration(parameters, playbooks_paths, qa_ctl_config_generator):
    """Generate the qa-ctl configuration according to the script parameters and write it into a file.
    Args:
        parameters (argparse.Namespace): Object with the user parameters.
        playbooks_paths (list(list)): List with the playbooks paths to run with qa-ctl for each instance
        qa_ctl_config_generator (QACTLConfigGenerator): qa-ctl config generator object.
    Returns:
        str: Configuration file path where the qa-ctl configuration has been saved.
    """

    logger.info('Generating qa-ctl configuration')

    current_timestamp = str(get_current_timestamp()).replace('.', '_')
    config_file_path = os.path.join(TMP_FILES, f"prevent_same_key_config_{current_timestamp}.yaml")
    os_system = parameters.os_system
    manager = ConfigInstance(f"manager_prevent_same_key_config_{os_system}_{current_timestamp}", os_system)
    agent_1 = ConfigInstance(f"agent_1_prevent_same_key_config_{os_system}_{current_timestamp}", os_system)
    agent_2 = ConfigInstance(f"agent_2_prevent_same_key_config_{os_system}_{current_timestamp}", os_system)

    true_instances = [manager, agent_1, agent_2]
    tasks_instances_order = [
        manager, agent_1, agent_2, agent_1, agent_2, manager, agent_2, agent_1, manager, agent_2, manager
    ]
    if parameters.auto_enrollment:
        tasks_instances_order = tasks_instances_order[:6]

    deployment_configuration = qa_ctl_config_generator.get_deployment_configuration(true_instances)
    tasks_configuration = qa_ctl_config_generator.get_tasks_configuration(playbooks_paths,
                                                                          instances=tasks_instances_order)

    qa_ctl_configuration = {**deployment_configuration, **tasks_configuration}

    file.write_yaml_file(config_file_path, qa_ctl_configuration)
    test_build_files.append(config_file_path)

    logger.info(f"The qa-ctl configuration has been created successfully in {config_file_path}")

    return config_file_path


def main():
    parameters = get_parameters()
    validate_parameters(parameters)

    current_timestamp = str(get_current_timestamp()).replace('.', '_')
    # Define the file path where the client.keys will be stored in the 'control machine'
    local_client_keys_file_path = os.path.join(TMP_FILES, "client.keys")
    # Define the file path where the matched lines of the log will be stored in the 'control machine'
    local_log_output_file_path = os.path.join(TMP_FILES, "log_output.txt")
    local_agent_ctl_output_file_path = os.path.join(TMP_FILES, "control_output.json")

    test_build_files.extend([local_client_keys_file_path, local_log_output_file_path, local_agent_ctl_output_file_path])

    # Define the directory path where the tests result will be stored
    test_output_path = parameters.output_file_path if parameters.output_file_path else \
        os.path.join(TMP_FILES, f"test_prevent_same_key_configuration_results_{current_timestamp}")

    set_environment(parameters, None if parameters.output_file_path else test_output_path)

    qa_ctl_config_generator = QACTLConfigGenerator()
    try:
        list_of_playbooks_info = generate_test_playbooks(parameters, qa_ctl_config_generator,
                                                         local_client_keys_file_path, local_log_output_file_path,
                                                         local_agent_ctl_output_file_path)

        for playbooks_info in list_of_playbooks_info:
            test_build_files.extend([playbook_path for playbook_path in playbooks_info.values()])

        qa_ctl_config_file_path = generate_qa_ctl_configuration(parameters, list_of_playbooks_info,
                                                                qa_ctl_config_generator)

        qa_ctl_extra_args = '' if parameters.debug == 0 else ('-d' if parameters.debug == 1 else '-dd')
        qa_ctl_extra_args += ' -p' if parameters.persistent else ''
        local_actions.run_local_command_printing_output(f"qa-ctl -c {qa_ctl_config_file_path} {qa_ctl_extra_args}")

        file_become_valid_json(local_agent_ctl_output_file_path)

        test_parameters = f" --control-output '{local_agent_ctl_output_file_path}'"
        if not parameters.auto_enrollment:
            test_parameters += f" --log-output '{local_log_output_file_path}'"

        pytest_command = f"cd {TEST_PREVENT_SAME_KEY_CONFIG_PATH} && python3 -m pytest " \
                         f"test_prevent_same_key_configuration {test_parameters}"

        try:
            test_result = local_actions.run_local_command_returning_output(pytest_command)
            assert 'AssertionError' not in test_result, "Some tests have failed."
        finally:
            file.write_file(os.path.join(test_output_path, 'pytest_result.txt'), test_result)
            logger.info(f"The tests result has been stored in {test_output_path}/pytest_result.txt")

    finally:
        if parameters and not parameters.persistent:
            logger.info('Deleting all test artifacts files of this build (config files, playbooks, data results ...)')
            for file_to_remove in test_build_files:
                file.remove_file(file_to_remove)


if __name__ == '__main__':
    main()
