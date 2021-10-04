# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import json
import argparse
import os
import yaml

from jsonschema import validate
from tempfile import gettempdir

from wazuh_testing.qa_ctl.deployment.qa_infraestructure import QAInfraestructure
from wazuh_testing.qa_ctl.provisioning.qa_provisioning import QAProvisioning
from wazuh_testing.qa_ctl.run_tests.qa_test_runner import QATestRunner
from wazuh_testing.qa_ctl.configuration.qa_ctl_configuration import QACTLConfiguration
from wazuh_testing.qa_ctl import QACTL_LOGGER
from wazuh_testing.tools.logging import Logging
from wazuh_testing.tools.exceptions import QAValueError
from wazuh_testing.qa_ctl.configuration.config_generator import QACTLConfigGenerator
from wazuh_testing.tools.github_repository import version_is_released, branch_exist, WAZUH_QA_REPO
from wazuh_testing.qa_ctl.provisioning import local_actions
from wazuh_testing.tools.github_repository import get_last_wazuh_version


DEPLOY_KEY = 'deployment'
PROVISION_KEY = 'provision'
TEST_KEY = 'tests'
WAZUH_QA_FILES = os.path.join(gettempdir(), 'wazuh-qa')

qactl_logger = Logging(QACTL_LOGGER)
_data_path = os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))), 'data')
launched = {
    'config_generator': False,
    'instance_handler': False,
    'qa_provisioning': False,
    'test_runner': False
}


def read_configuration_data(configuration_file_path):
    """Read qa-ctl configuration data file as yaml and returns it as a dictionary.

    Args:
        configuration_file_path (string): Local path where is localted the qa-ctl configuration file.
    """
    qactl_logger.debug('Reading configuration_data')
    with open(configuration_file_path) as config_file_fd:
        configuration_data = yaml.safe_load(config_file_fd)
    qactl_logger.debug('The configuration data has been read successfully')

    return configuration_data


def validate_configuration_data(configuration_data):
    """Validate the configuration data schema.

    Args:
        configuration_data (dict): Configuration data info.
    """
    qactl_logger.debug('Validating configuration schema')
    data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'data')
    schema_file = os.path.join(data_path, 'qactl_conf_validator_schema.json')

    with open(os.path.join(_data_path, schema_file), 'r') as config_data:
        schema = json.load(config_data)

    validate(instance=configuration_data, schema=schema)

    qactl_logger.debug('Schema validation has passed successfully')


def set_qactl_logging(qactl_configuration):
    """Set qa-ctl logging configuration according to the config section of the qa-ctl configuration file.

    Args:
        qactl_configuration (dict): Configuration data info.
    """
    if not qactl_configuration.logging_enable:
        qactl_logger.disable()
    else:
        qactl_logger.enable()
        qactl_logger.set_level(qactl_configuration.logging_level)
        qactl_logger.stdout = True
        qactl_logger.logging_file = qactl_configuration.logging_file
        qactl_logger.update_configuration()


def set_parameters(parameters):
    """Update script parameters and add extra information.

    Args:
        (argparse.Namespace): Object with the user parameters.
    """
    if parameters.no_validation_logging:
        qactl_logger.disable()
    else:
        level = 'DEBUG' if parameters.debug >= 1 else 'INFO'
        qactl_logger.set_level(level)

    parameters.user_version = parameters.version if parameters.version else None
    parameters.version = parameters.version if parameters.version  else get_last_wazuh_version()
    parameters.version = (parameters.version).replace('v', '')

    short_version =  f"{(parameters.version).split('.')[0]}.{(parameters.version).split('.')[1]}"
    parameters.qa_branch = parameters.qa_branch if parameters.qa_branch else short_version


def set_environment(parameters):
    """Prepare the local environment to be run.

    Args:
        (argparse.Namespace): Object with the user parameters.
    """
    if parameters.run_test:
        # Download wazuh-qa repository locally to run qa-docs tool and get the tests info
        local_actions.download_local_wazuh_qa_repository(branch=parameters.qa_branch, path=gettempdir())


def validate_parameters(parameters):
    """Validate the input parameters entered by the user of qa-ctl tool.

    Args:
        parameters (argparse.Namespace): Object with the user parameters.

    Raises:
        QAValueError: If parameters are incompatible, or version has not a valid format, or the specified wazuh version
                      has not been released, or wazuh QA branch does not exist (calculated from wazuh_version).
    """
    qactl_logger.info('Validating input parameters')

    # Check incompatible parameters
    if parameters.config and parameters.run_test:
        raise QAValueError('The --run parameter is incompatible with --config. --run will autogenerate the '
                           'configuration', qactl_logger.error, QACTL_LOGGER)

    if parameters.user_version and parameters.run_test is None:
        raise QAValueError('The -v, --version parameter can only be used with -r, --run', qactl_logger.error)

    if parameters.dry_run and parameters.run_test is None:
        raise QAValueError('The --dry-run parameter can only be used with -r, --run', qactl_logger.error, QACTL_LOGGER)

    # Check version parameter
    if len((parameters.version).split('.')) != 3:
        raise QAValueError(f"Version parameter has to be in format x.y.z. You entered {parameters.version}",
                           qactl_logger.error, QACTL_LOGGER)

    # Check if Wazuh has the specified version
    if not version_is_released(parameters.version):
        raise QAValueError(f"The wazuh {parameters.version} version has not been released. Enter a right version.",
                           qactl_logger.error, QACTL_LOGGER)

    # Check if QA branch exists
    if not branch_exist(parameters.qa_branch, WAZUH_QA_REPO):
        raise QAValueError(f"{parameters.qa_branch} branch does not exist in Wazuh QA repository.",
                           qactl_logger.error, QACTL_LOGGER)

    # Check if specified tests exist. Wazuh-qa repository needs to be downloaded locally before.
    if parameters.run_test:
        for test in parameters.run_test:
            tests_path = os.path.join(WAZUH_QA_FILES, 'tests')
            if 'test exists' not in local_actions.run_local_command_with_output(f"qa-docs -e {test} -I {tests_path}"):
                raise QAValueError(f"{test} does not exist in {tests_path}", qactl_logger.error, QACTL_LOGGER)

    qactl_logger.info('Input parameters validation has passed successfully')


def get_script_parameters():
    """Handle the script parameters. It capturates and validates them.

    Returns:
        argparse.Namespace: Object with the script parameters.
    """
    parser = argparse.ArgumentParser()

    parser.add_argument('--config', '-c', type=str, action='store', required=False, dest='config',
                        help='Path to the configuration file.')

    parser.add_argument('-p', '--persistent', action='store_true',
                        help='Persistent instance mode. Do not destroy the instances once the process has finished.')

    parser.add_argument('--dry-run', action='store_true',
                        help='Config generation mode. The test data will be processed and the configuration will be '
                             'generated without running anything.')

    parser.add_argument('--run', '-r', type=str, action='store', required=False, nargs='+', dest='run_test',
                        help='Independent run method. Specify a test or a list of tests to be run')

    parser.add_argument('--version', '-v', type=str, action='store', required=False, dest='version',
                        help='Wazuh installation and tests version')

    parser.add_argument('-d', '--debug', action='count', default=0, help='Run in debug mode. You can increase the debug'
                                                                         ' level with more [-d+]')
    parser.add_argument('--no-validation-logging', action='store_true', help='Disable initial logging of parameter '
                                                                             'validations')

    parser.add_argument('--qa-branch', type=str, action='store', required=False, dest='qa_branch',
                                       help='Set a custom wazuh-qa branch to use in the run and provisioning. This '
                                            'has higher priority than the specified in the configuration file')
    arguments = parser.parse_args()

    return arguments


def main():
    configuration_data = {}
    instance_handler = None
    configuration_file = None

    arguments = get_script_parameters()

    set_parameters(arguments)

    set_environment(arguments)

    validate_parameters(arguments)

    # Generate or get the qactl configuration file
    if arguments.run_test:
        qactl_logger.debug('Generating configuration file')
        config_generator = QACTLConfigGenerator(arguments.run_test, arguments.version, arguments.qa_branch,
                                                WAZUH_QA_FILES)
        config_generator.run()
        launched['config_generator'] = True
        configuration_file = config_generator.config_file_path
        qactl_logger.debug(f"Configuration file has been created sucessfully in {configuration_file}")

        # If dry-run mode, then exit after generating the configuration file
        if arguments.dry_run:
            qactl_logger.info(f"Run as dry-run mode. Configuration file saved in {config_generator.config_file_path}")
            return 0
    else:
        configuration_file = arguments.config

    # Check configuration file path exists
    if not os.path.exists(configuration_file):
        raise QAValueError(f"{configuration_file} file doesn't exists or could not be generated correctly",
                           qactl_logger.error, QACTL_LOGGER)

    # Read configuration data
    configuration_data = read_configuration_data(configuration_file)

    # Validate configuration schema
    validate_configuration_data(configuration_data)

    # Set QACTL configuration
    qactl_configuration = QACTLConfiguration(configuration_data, arguments)

    # Set QACTL logging
    set_qactl_logging(qactl_configuration)

    # Run QACTL modules
    try:
        if DEPLOY_KEY in configuration_data:
            deploy_dict = configuration_data[DEPLOY_KEY]
            instance_handler = QAInfraestructure(deploy_dict, qactl_configuration)
            instance_handler.run()
            launched['instance_handler'] = True

        if PROVISION_KEY in configuration_data:
            provision_dict = configuration_data[PROVISION_KEY]
            qa_provisioning = QAProvisioning(provision_dict, qactl_configuration)
            qa_provisioning.run()
            launched['qa_provisioning'] = True

        if TEST_KEY in configuration_data:
            test_dict = configuration_data[TEST_KEY]
            tests_runner = QATestRunner(test_dict, qactl_configuration)
            tests_runner.run()
            launched['test_runner'] = True
    finally:
        if not arguments.persistent:
            if DEPLOY_KEY in configuration_data and launched['instance_handler']:
                instance_handler.destroy()

            if PROVISION_KEY in configuration_data and launched['qa_provisioning']:
                qa_provisioning.destroy()

            if TEST_KEY in configuration_data and launched['test_runner']:
                tests_runner.destroy()

            if arguments.run_test and launched['config_generator']:
                config_generator.destroy()

if __name__ == '__main__':
    main()
