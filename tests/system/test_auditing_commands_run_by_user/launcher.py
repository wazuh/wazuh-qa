# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2


import argparse
import json
import os
import sys
from tempfile import gettempdir

from wazuh_testing.qa_ctl import QACTL_LOGGER
from wazuh_testing.qa_ctl.configuration.config_generator import QACTLConfigGenerator
from wazuh_testing.qa_ctl.provisioning import local_actions
from wazuh_testing.tools import file, github_checks
from wazuh_testing.tools.exceptions import QAValueError
from wazuh_testing.tools.github_api_requests import WAZUH_QA_REPO
from wazuh_testing.tools.logging import Logging
from wazuh_testing.tools.time import get_current_timestamp
from wazuh_testing.tools.s3_package import get_production_package_url, get_last_production_package_url
from wazuh_testing.qa_ctl.provisioning.ansible import playbook_generator
from wazuh_testing.qa_ctl.configuration.config_instance import ConfigInstance

TMP_FILES = os.path.join(gettempdir(), 'wazuh_auditing_commands')
WAZUH_QA_FILES = os.path.join(TMP_FILES, 'wazuh-qa')
AUDITING_USER_COMMANDS_TEST_PATH = os.path.join(WAZUH_QA_FILES, 'tests', 'system')

logger = Logging(QACTL_LOGGER)
test_build_files = []


def get_parameters():
    """
    Returns:
        argparse.Namespace: Object with the user parameters.
    """
    parser = argparse.ArgumentParser()

    parser.add_argument('--os', '-o', type=str, action='store', required=False, dest='os_system',
                        choices=['centos_7', 'centos_8'], default='centos_8')

    parser.add_argument('--version', '-v', type=str, action='store', required=False, dest='wazuh_version',
                        help='Wazuh installation and tests version.')

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


def set_environment(parameters):
    """Prepare the local environment for the test run.

    Args:
        parameters (argparse.Namespace): Object with the user parameters.

    """
    set_logger(parameters)

    local_actions.download_local_wazuh_qa_repository(branch=parameters.qa_branch, path=TMP_FILES)
    test_build_files.append(WAZUH_QA_FILES)

    if parameters.output_file_path:
        file.recursive_directory_creation(parameters.output_file_path)


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
    config_file_path = os.path.join(TMP_FILES, f"auditing_commands_config_{current_timestamp}.yaml")
    os_system = parameters.os_system

    manager_instance_name = f"manager_auditing_commands_{os_system}_{current_timestamp}"
    agent_instance_name = f"agent_auditing_commands_{os_system}_{current_timestamp}"
    manager_instance = ConfigInstance(manager_instance_name, os_system)
    agent_instance = ConfigInstance(agent_instance_name, os_system)
    instances = [manager_instance, agent_instance, manager_instance]

    deployment_configuration = qa_ctl_config_generator.get_deployment_configuration(instances[:2])
    tasks_configuration = qa_ctl_config_generator.get_tasks_configuration(playbooks_paths, instances=instances)

    qa_ctl_configuration = {**deployment_configuration, **tasks_configuration}

    file.write_yaml_file(config_file_path, qa_ctl_configuration)
    test_build_files.append(config_file_path)

    logger.info(f"The qa-ctl configuration has been created successfully in {config_file_path}")

    return config_file_path


def generate_test_playbooks(parameters, qa_ctl_config_generator, alerts_local_destination):
    """Generate the necessary playbooks to run the test.
    Args:
        parameters (argparse.Namespace): Object with the user parameters.
        qa_ctl_config_generator (QACTLConfigGenerator): QACTLConfigGenerator object.
        alerts_local_destination (str): The local path where the alerts log will be stored.

    Returns:
        list(dict): List of dictionaries with information about playbooks.
    """
    manager_playbooks_info = {}
    secondary_manager_playbooks_info = {}
    agent_playbooks_info = {}

    manager_package_url = get_production_package_url('manager', parameters.os_system, parameters.wazuh_version) \
        if parameters.wazuh_version else get_last_production_package_url('manager', parameters.os_system)
    manager_package_name = os.path.split(manager_package_url)[1]
    agent_package_url = get_production_package_url('agent', parameters.os_system, parameters.wazuh_version) \
        if parameters.wazuh_version else get_last_production_package_url('agent', parameters.os_system)
    agent_package_name = os.path.split(agent_package_url)[1]

    os_platform = 'linux'
    vm_package_destination = '/tmp'
    alerts_vm_output_path = '/alerts_data_output.json'
    save_alerts_command = f'cp -v /var/ossec/logs/alerts/alerts.json {alerts_vm_output_path}'
    wazuh_rules_vm_path = '/etc/audit/rules.d/wazuh.rules'
    generate_auditd_rule_commands = [
        f'echo "-a exit,always -F euid=$(id -u vagrant) -F arch=b32 -S execve -k audit-wazuh-c" >>'
        f' {wazuh_rules_vm_path}',
        f'echo "-a exit,always -F euid=$(id -u vagrant) -F arch=b64 -S execve -k audit-wazuh-c" >>'
        f' {wazuh_rules_vm_path}',
        'auditctl -D',
        f'auditctl -R {wazuh_rules_vm_path}',
    ]
    audited_user_command = 'ping -c 4 www.google.com'

    # Playbooks parameters

    manager_install_playbook_parameters = {
        'wazuh_target': 'manager', 'package_name': manager_package_name,
        'package_url': manager_package_url, 'package_destination': vm_package_destination,
        'os_system': parameters.os_system, 'os_platform': os_platform
    }

    manager_ip = qa_ctl_config_generator.get_host_ip()
    qa_ctl_config_generator.delete_ip_entry(manager_ip)

    agent_install_playbook_parameters = {
        'wazuh_target': 'agent', 'package_name': agent_package_name,
        'package_url': agent_package_url, 'package_destination': vm_package_destination,
        'os_system': parameters.os_system, 'os_platform': os_platform, 'manager_ip': manager_ip
    }

    generate_auditd_alert_playbook_parameters = {
        'commands': generate_auditd_rule_commands,
        'playbook_parameters': {'become': True}
    }

    user_command_playbook_parameters = {
        'commands': [audited_user_command]
    }

    save_alerts_command_playbook_parameters = {
        'commands': [save_alerts_command],
        'playbook_parameters': {'become': True}
    }

    fetch_files_playbooks_parameters = {
        'files_data': {alerts_vm_output_path: alerts_local_destination},
        'playbook_parameters': {'become': True}
    }

    # Playbooks generation

    manager_playbooks_info.update({'install_manager': playbook_generator.install_wazuh(
        **manager_install_playbook_parameters)})

    agent_playbooks_info.update({'install_agent': playbook_generator.install_wazuh(
        **agent_install_playbook_parameters)})

    agent_playbooks_info.update({'waiting_time_before_generate_alerts': playbook_generator.wait_seconds(30)})

    agent_playbooks_info.update({'generate_auditd_rules': playbook_generator.run_linux_commands(
        **generate_auditd_alert_playbook_parameters)})

    agent_playbooks_info.update({'execute_user_command':
                                 playbook_generator.run_linux_commands(**user_command_playbook_parameters)})

    secondary_manager_playbooks_info.update({'waiting_time_before_fetch_alerts_file': playbook_generator.wait_seconds(
        5)})

    secondary_manager_playbooks_info.update({'copy_alerts_log': playbook_generator.run_linux_commands(
        **save_alerts_command_playbook_parameters)})

    secondary_manager_playbooks_info.update({'fetch_alerts_file': playbook_generator.fetch_files(
        **fetch_files_playbooks_parameters)})

    return manager_playbooks_info, agent_playbooks_info, secondary_manager_playbooks_info


def main():
    parameters = get_parameters()
    validate_parameters(parameters)
    qa_ctl_config_generator = QACTLConfigGenerator()
    current_timestamp = str(get_current_timestamp()).replace('.', '_')
    alerts_data_path = os.path.join(TMP_FILES, f"alerts_data_{current_timestamp}.json")
    expected_alert_data = {
        "execve": {
            "a0": "ping",
            "a1": "-c",
            "a2": "4",
            "a3": "www.google.com"
        }
    }
    test_output_path = parameters.output_file_path if parameters.output_file_path else \
        os.path.join(TMP_FILES, f"test_auditing_commands_result_{current_timestamp}")
    if os.path.exists(test_output_path) and not os.path.isdir(test_output_path):
        raise ValueError(f"The given output path {test_output_path} already exists and is not a directory.")
    elif not os.path.exists(test_output_path):
        os.makedirs(test_output_path)

    set_environment(parameters)

    try:
        list_of_playbooks_info = generate_test_playbooks(parameters, qa_ctl_config_generator, alerts_data_path)
        for playbooks_info in list_of_playbooks_info:
            test_build_files.extend([playbook_path for playbook_path in playbooks_info.values()])

        qa_ctl_extra_args = '' if parameters.debug == 0 else ('-d' if parameters.debug == 1 else '-dd')
        qa_ctl_extra_args += ' -p' if parameters.persistent else ''

        qa_ctl_config_file_path = generate_qa_ctl_configuration(
            parameters, list_of_playbooks_info, qa_ctl_config_generator
        )

        local_actions.run_local_command_printing_output(f"qa-ctl -c {qa_ctl_config_file_path} {qa_ctl_extra_args}")

        pytest_command = f"cd {AUDITING_USER_COMMANDS_TEST_PATH} && python3 -m pytest " \
                         f"test_auditing_commands_run_by_user/ --alerts-file " \
                         f"'{alerts_data_path}' --expected-data '{json.dumps(expected_alert_data)}'"
        print(pytest_command)

        try:
            # Run the pytest
            test_result = local_actions.run_local_command_returning_output(pytest_command)

            # Check the test result
            assert 'AssertionError' not in test_result, "The 'test_auditing_commands_run_by_user' has failed"

        finally:
            # Save pytest result if the pytest has been launched
            file.write_file(os.path.join(test_output_path, 'pytest_result.txt'), test_result)
            logger.info(f"The test results have been stored in {test_output_path}/pytest_result.txt")
            print(test_result)
    finally:
        if parameters and not parameters.persistent:
            logger.info('Deleting all test artifacts files of this build (config files, playbooks, data results ...)')
            for file_to_remove in test_build_files:
                file.remove_file(file_to_remove)


if __name__ == '__main__':
    main()
