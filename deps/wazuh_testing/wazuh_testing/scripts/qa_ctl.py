# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import json
import argparse
import os
import sys
import yaml
import textwrap

from jsonschema import validate
from tempfile import gettempdir

from wazuh_testing.qa_ctl.deployment.qa_infraestructure import QAInfraestructure
from wazuh_testing.qa_ctl.provisioning.qa_provisioning import QAProvisioning
from wazuh_testing.qa_ctl.run_tests.qa_test_runner import QATestRunner
from wazuh_testing.qa_ctl.run_tasks.qa_tasks_launcher import QATasksLauncher
from wazuh_testing.qa_ctl.configuration.qa_ctl_configuration import QACTLConfiguration
from wazuh_testing.qa_ctl import QACTL_LOGGER
from wazuh_testing.tools.logging import Logging
from wazuh_testing.tools.exceptions import QAValueError
from wazuh_testing.qa_ctl.configuration.config_generator import QACTLConfigGenerator
from wazuh_testing.tools import github_checks
from wazuh_testing.tools import file
from wazuh_testing.tools.github_api_requests import WAZUH_QA_REPO
from wazuh_testing.qa_ctl.provisioning import local_actions
from wazuh_testing.tools.file import recursive_directory_creation


DEPLOY_KEY = 'deployment'
PROVISION_KEY = 'provision'
TASKS_KEY = 'tasks'
TEST_KEY = 'tests'
WAZUH_QA_FILES = os.path.join(gettempdir(), 'wazuh_qa_ctl', 'wazuh-qa')
RUNNING_ON_DOCKER_CONTAINER = True if 'RUNNING_ON_DOCKER_CONTAINER' in os.environ else False
AUTOMATIC_MODE = 'manual_mode'
MANUAL_MODE = 'automatic_mode'


qactl_logger = Logging(QACTL_LOGGER)
_data_path = os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))), 'data')
launched = {
    'config_generator': False,
    'instance_handler': False,
    'qa_provisioning': False,
    'tasks_runner': False,
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


def validate_configuration_data(configuration_data, qa_ctl_mode):
    """Validate the configuration data schema.

    Args:
        configuration_data (dict): Configuration data info.
        qa_ctl_mode (str): qa-ctl run mode (AUTOMATIC_MODE or MANUAL_MODE)
    """
    qactl_logger.debug('Validating configuration schema')
    data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'data')
    schema_file = os.path.join(data_path, 'qactl_conf_validator_schema.json')

    with open(os.path.join(_data_path, schema_file), 'r') as config_data:
        schema = json.load(config_data)

    # Validate schema constraints
    validate(instance=configuration_data, schema=schema)

    # Check that qa_ctl_launcher_branch parameter has been specified and its valid for Windows manual mode
    if sys.platform == 'win32' and qa_ctl_mode == MANUAL_MODE:
        if 'config' not in configuration_data or 'qa_ctl_launcher_branch' not in configuration_data['config']:
            raise QAValueError('qa_ctl_launcher_branch was not found in the configuration file. It is required if '
                               'you are running qa-ctl in a Windows host', qactl_logger.error, QACTL_LOGGER)

        # Check that qa_ctl_launcher_branch exists
        if not github_checks.branch_exists(configuration_data['config']['qa_ctl_launcher_branch'],
                                           repository=WAZUH_QA_REPO):
            raise QAValueError(f"{configuration_data['config']['qa_ctl_launcher_branch']} branch specified as "
                               'qa_ctl_launcher_branch  does not exist in Wazuh QA repository.', qactl_logger.error,
                               QACTL_LOGGER)

    qactl_logger.debug('Schema validation has passed successfully')


def check_test_module_exists(tests_path, type, component, suite_command, module):
    """Check that the module exists.

    Args:
        tests_path (str): Path where the tests with the documentation are.
        type (str): Test type.
        component (str): Test component.
        suite_command (str): Suite flag and name to be used in the qa-docs run.
        module (str): Test module.
    """
    check_test_exist = f"qa-docs -p {tests_path} -t {type} -c {component} {suite_command} -e {module} --no-logging"
    check_test_exist = local_actions.run_local_command_returning_output(check_test_exist)
    if f"{module} exists" not in check_test_exist:
        raise QAValueError(f"{module} does not exist in {tests_path}", qactl_logger.error, QACTL_LOGGER)


def check_test_module_documentation(tests_path, type, component, suite_command, module):
    """Check that the module is documented.

    Args:
        tests_path (str): Path where the tests with the documentation are.
        type (str): Test type.
        component (str): Test component.
        suite_command (str): Suite flag and name to be used in the qa-docs run.
        module (str): Test module.
    """
    test_documentation_check = f"qa-docs -p {tests_path} -t {type} -c {component} {suite_command} -m {module} " \
                               '--no-logging --check-documentation'
    test_documentation_check = local_actions.run_local_command_returning_output(test_documentation_check)
    if f'{module} is not documented' in test_documentation_check:
        raise QAValueError(f"{module} is not documented using qa-docs current schema", qactl_logger.error,
                           QACTL_LOGGER)

def validate_test_module(type=None, component=None, suite=None, module=None):
    """Check that the module exists and is documented.

    Args:
        type (str): Test type.
        component (str): Test component.
        suite (str): Test suite.
        module (str): Test module.
    """
    tests_path = os.path.join(WAZUH_QA_FILES, 'tests')
    suite_command = f"-s {suite}" if suite is not None else ''

    check_test_module_exists(tests_path, type, component, suite_command, module)
    check_test_module_documentation(tests_path, type, component, suite_command, module)


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

    Raises:
        QAValueError: If could not find a valid wazuh tag in the first github tags page (It can happen if on the first
                      page, all tags are rc tags.).

    Args:
        (argparse.Namespace): Object with the user parameters.
    """
    if parameters.no_validation_logging:
        qactl_logger.disable()
    else:
        level = 'DEBUG' if parameters.debug >= 1 else 'INFO'
        qactl_logger.set_level(level)

        # Disable traceback if it is not run in DEBUG mode
        if level != 'DEBUG':
            sys.tracebacklimit = 0

    parameters.user_version = parameters.version if parameters.version else None

    try:
        parameters.version = parameters.version if parameters.version else github_checks.get_last_wazuh_version()
    except QAValueError:
        raise QAValueError('The latest version of Wazuh could not be obtained. Maybe there is no valid (non-rc) one at '
                           'https://github.com/wazuh/wazuh/tags. Try specifying the version manually using the '
                           '--version <value> parameter in the qa-ctl parameters.', qactl_logger.error, QACTL_LOGGER)

    parameters.version = (parameters.version).replace('v', '')
    parameters.test_modules = [module.replace('.py', '') for module in parameters.test_modules]

    short_version = f"{(parameters.version).split('.')[0]}.{(parameters.version).split('.')[1]}"
    parameters.qa_branch = parameters.qa_branch if parameters.qa_branch else short_version


def set_environment(parameters):
    """Prepare the local environment to be run.

    Args:
        (argparse.Namespace): Object with the user parameters.
    """
    # Create the wazuh_qa_ctl temporary folder
    recursive_directory_creation(os.path.join(gettempdir(), 'wazuh_qa_ctl'))

    if parameters.run:
        # Download wazuh-qa repository locally to run qa-docs tool and get the tests info
        local_actions.download_local_wazuh_qa_repository(branch=parameters.qa_branch,
                                                         path=os.path.join(gettempdir(), 'wazuh_qa_ctl'))


def validate_parameters(parameters):
    """Validate the input parameters entered by the user of qa-ctl tool.

    Args:
        parameters (argparse.Namespace): Object with the user parameters.

    Raises:
        QAValueError: If parameters are incompatible, or version has not a valid format, or the specified wazuh version
                      has not been released, or wazuh QA branch does not exist (calculated from wazuh_version).
    """
    def _validate_tests_os(parameters):
        for type, component, suite, module in zip(parameters.test_types, parameters.test_components,
                                                  parameters.test_suites, parameters.test_modules):
            tests_path = os.path.join(WAZUH_QA_FILES, 'tests')
            test_documentation_command = f"qa-docs -p {tests_path} -t {type} -c {component} -s {suite} -m {module} " \
                                         f"-o {gettempdir()} --no-logging"
            test_documentation_file_path = os.path.join(gettempdir(), f"output/{module}.json")
            local_actions.run_local_command_returning_output(test_documentation_command)

            test_data = json.loads(file.read_file(test_documentation_file_path))

            for op_system in parameters.operating_systems:
                # Check platform
                platform = QACTLConfigGenerator.SYSTEMS[op_system]['os_platform'] if op_system in \
                    QACTLConfigGenerator.SYSTEMS.keys() else op_system
                if platform not in test_data['os_platform']:
                    raise QAValueError(f"The {module} module does not support the {op_system} system. Allowed "
                                       f"platforms: {test_data['os_platform']} (ubuntu and centos are from linux "
                                       'platform)')
                # Check os version
                if len([os_version.lower() for os_version in test_data['os_version'] if op_system in os_version]) > 0:
                    raise QAValueError(f"The {module} module does not support the {op_system} system. Allowed operating"
                                       f" system versions: {test_data['os_version']}")
            # Clean the temporary files
            for extension in ['.json', '.yaml']:
                file.remove_file(os.path.join(gettempdir(), f"{module}{extension}"))

    qactl_logger.info('Validating input parameters')

    # Check incompatible parameters
    if parameters.config and parameters.run:
        raise QAValueError('The --run parameter is incompatible with --config. --run will autogenerate the '
                           'configuration', qactl_logger.error, QACTL_LOGGER)

    # Check that run flag has the minimal test module information
    if parameters.run and not (parameters.test_components and parameters.test_modules):
        raise QAValueError('The --run parameter needs the component, suite and module to run a test. You can specify '
                           'them with --test-components, --test-suites and --test-modules.',
                           qactl_logger.error, QACTL_LOGGER)

    # Check that the test flags have the same lenght
    if parameters.run:
        if len(parameters.test_types) != len(parameters.test_components) or  \
        (len(parameters.test_types) != len(parameters.test_suites) and parameters.test_suites) or \
        len(parameters.test_types) != len(parameters.test_modules):
            raise QAValueError('The parameters that specify the modules, suites, components, and types must have the '
                               'same length: --test-types, --test-components, --test-suites and --test_modules.',
                               qactl_logger.error, QACTL_LOGGER)

    if parameters.user_version and parameters.run is None:
        raise QAValueError('The -v, --version parameter can only be used with -r, --run', qactl_logger.error)

    if parameters.dry_run and parameters.run is None:
        raise QAValueError('The --dry-run parameter can only be used with -r, --run', qactl_logger.error, QACTL_LOGGER)

    if (parameters.skip_deployment or parameters.skip_provisioning or parameters.skip_testing) \
       and not parameters.config:
        raise QAValueError('The --skip parameter can only be used when a custom configuration file has been '
                           'specified with the option -c or --config', qactl_logger.error, QACTL_LOGGER)

    # Check version parameter
    if len((parameters.version).split('.')) != 3:
        raise QAValueError(f"Version parameter has to be in format x.y.z. You entered {parameters.version}",
                           qactl_logger.error, QACTL_LOGGER)

    # Check if Wazuh has the specified version
    if not github_checks.version_is_released(parameters.version):
        raise QAValueError(f"The wazuh {parameters.version} version has not been released. Enter a right version.",
                           qactl_logger.error, QACTL_LOGGER)

    # Check if QA branch exists
    if not github_checks.branch_exists(parameters.qa_branch, repository=WAZUH_QA_REPO):
        raise QAValueError(f"{parameters.qa_branch} branch does not exist in Wazuh QA repository.",
                           qactl_logger.error, QACTL_LOGGER)

    # Check if specified tests exist. Wazuh-qa repository needs to be downloaded locally before.
    if parameters.run:
        if parameters.test_suites:
            for type, component, suite, module in zip(parameters.test_types, parameters.test_components,
                                                      parameters.test_suites, parameters.test_modules):
                validate_test_module(type, component, suite, module)
        else:
            for type, component, module in zip(parameters.test_types, parameters.test_components,
                                               parameters.test_modules):
                validate_test_module(type, component, module=module)

    # Validate the tests operating system compatibility if specified
    if parameters.operating_systems:
        _validate_tests_os(parameters)

    qactl_logger.info('Input parameters validation has passed successfully')


def get_script_parameters():
    """Handle the script parameters. It capturates and validates them.

    Returns:
        argparse.Namespace: Object with the script parameters.
    """
    description = \
        '''
        Current version: v0.3.1

        Description: qa-ctl is a tool for launching tests locally, automating the deployment, provisioning and testing
                     phase.

                     You can find more information in https://github.com/wazuh/wazuh-qa/wiki/QACTL-tool
        '''

    parser = argparse.ArgumentParser(description=textwrap.dedent(description),
                                     formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument('--config', '-c', type=str, action='store', required=False, dest='config',
                        help='Path to the configuration file.')

    parser.add_argument('--persistent', '-p', action='store_true',
                        help='Persistent instance mode. Do not destroy the instances once the process has finished.')

    parser.add_argument('--dry-run', action='store_true',
                        help='Config generation mode. The test data will be processed and the configuration will be '
                             'generated without running anything.')

    parser.add_argument('--run', '-r', action='store_true',
                        help='Independent run method. The tests that the user has specified will be run.')

    parser.add_argument('--test-types', type=str, action='store', required=False, nargs='+', dest='test_types',
                        default=['integration'],
                        help='Specify the types of the tests to be run.')

    parser.add_argument('--test-components', type=str, action='store', required=False, nargs='+',
                        dest='test_components', default=[],
                        help='Specify the components of the tests to be run.')

    parser.add_argument('--test-suites', type=str, action='store', required=False, nargs='+', dest='test_suites',
                        default=[],
                        help='Specify the suites of the tests to be run.')

    parser.add_argument('--test-modules', type=str, action='store', required=False, nargs='+', dest='test_modules',
                        default=[],
                        help='Specify the modules that contain the tests to be run.')

    parser.add_argument('--version', '-v', type=str, action='store', required=False, dest='version',
                        help='Wazuh installation and tests version.')

    parser.add_argument('--debug', '-d', action='count', default=0, help='Run in debug mode. You can increase the debug'
                                                                         ' level with more [-d+]')
    parser.add_argument('--no-validation-logging', action='store_true', help='Disable initial logging of parameter '
                                                                             'validations.')

    parser.add_argument('--no-validation', action='store_true', help='Disable the script parameters validation.')

    parser.add_argument('--os', '-o', type=str, action='store', required=False, nargs='+', dest='operating_systems',
                        choices=['centos_7', 'centos_8', 'ubuntu_focal', 'windows_2019'],
                        help='System/s where the tests will be launched.')

    parser.add_argument('--qa-branch', type=str, action='store', required=False, dest='qa_branch',
                        help='Set a custom wazuh-qa branch to use in the run and provisioning. This '
                             'has higher priority than the specified in the configuration file.')

    parser.add_argument('--skip-deployment', action='store_true',
                        help='Flag to skip the deployment phase. Set it only if -c or --config was specified.')

    parser.add_argument('--skip-provisioning', action='store_true',
                        help='Flag to skip the provisioning phase. Set it only if -c or --config was specified.')

    parser.add_argument('--skip-tasks', action='store_true',
                        help='Flag to skip the tasks phase. Set it only if -c or --config was specified.')

    parser.add_argument('--skip-testing', action='store_true',
                        help='Flag to skip the testing phase. Set it only if -c or --config was specified.')

    arguments = parser.parse_args()

    return arguments


def main():
    configuration_data = {}
    instance_handler = None
    configuration_file = None

    arguments = get_script_parameters()

    set_parameters(arguments)

    set_environment(arguments)

    if not arguments.no_validation:
        validate_parameters(arguments)

    qa_ctl_mode = AUTOMATIC_MODE if arguments.run else MANUAL_MODE

    # Generate or get the qactl configuration file
    if qa_ctl_mode == AUTOMATIC_MODE:
        qactl_logger.debug('Generating configuration file')
        modules_data = {'types': [], 'components': [], 'suites': [], 'modules': []}

        if arguments.test_suites:
            for type, component, suite, module in zip(arguments.test_types, arguments.test_components,
                                                      arguments.test_suites, arguments.test_modules):
                modules_data['types'].append(type)
                modules_data['components'].append(component)
                modules_data['suites'].append(suite)
                modules_data['modules'].append(module)
        else:
            for type, component, module in zip(arguments.test_types, arguments.test_components,
                                               arguments.test_modules):
                modules_data['types'].append(type)
                modules_data['components'].append(component)
                modules_data['modules'].append(module)

        config_generator = QACTLConfigGenerator(modules_data, arguments.version, arguments.qa_branch,
                                                WAZUH_QA_FILES, arguments.operating_systems)
        config_generator.run()
        launched['config_generator'] = True
        configuration_file = config_generator.config_file_path
        qactl_logger.debug(f"Configuration file has been created successfully in {configuration_file}")

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
    validate_configuration_data(configuration_data, qa_ctl_mode)

    # Set QACTL configuration
    qactl_configuration = QACTLConfiguration(configuration_data, arguments)

    # Set QACTL logging
    set_qactl_logging(qactl_configuration)

    # Run QACTL modules
    try:
        if DEPLOY_KEY in configuration_data and not arguments.skip_deployment and not RUNNING_ON_DOCKER_CONTAINER:
            deploy_dict = configuration_data[DEPLOY_KEY]
            instance_handler = QAInfraestructure(deploy_dict, qactl_configuration)
            instance_handler.run()
            launched['instance_handler'] = True

        if PROVISION_KEY in configuration_data and not arguments.skip_provisioning:
            provision_dict = configuration_data[PROVISION_KEY]
            qa_provisioning = QAProvisioning(provision_dict, qactl_configuration)
            qa_provisioning.run()
            launched['qa_provisioning'] = True

        if TASKS_KEY in configuration_data and not arguments.skip_tasks:
            tasks_dict = configuration_data[TASKS_KEY]
            tasks_runner = QATasksLauncher(tasks_dict, qactl_configuration)
            tasks_runner.run()
            launched['tasks_runner'] = True

        if TEST_KEY in configuration_data and not arguments.skip_testing:
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

            if arguments.run and launched['config_generator']:
                config_generator.destroy()
        else:
            if not RUNNING_ON_DOCKER_CONTAINER and arguments.run:
                qactl_logger.info(f"Configuration file saved in {config_generator.config_file_path}")


if __name__ == '__main__':
    main()
