# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import json
import argparse
import os
import yaml

from jsonschema import validate

from wazuh_testing.qa_ctl.deployment.qa_infraestructure import QAInfraestructure
from wazuh_testing.qa_ctl.provisioning.qa_provisioning import QAProvisioning
from wazuh_testing.qa_ctl.run_tests.qa_test_runner import QATestRunner
from wazuh_testing.qa_ctl.configuration.qa_ctl_configuration import QACTLConfiguration
from wazuh_testing.qa_ctl import QACTL_LOGGER
from wazuh_testing.tools.logging import Logging
from wazuh_testing.qa_ctl.configuration.config_generator import QACTLConfigGenerator
from wazuh_testing.tools.github_repository import version_is_released, branch_exist, WAZUH_QA_REPO


DEPLOY_KEY = 'deployment'
PROVISION_KEY = 'provision'
TEST_KEY = 'tests'

qactl_logger = None
_data_path = os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))), 'data')
launched = {
    'instance_handler': False,
    'qa_provisioning': False,
    'test_runner': False
}


def read_configuration_data(configuration_file_path):
    with open(configuration_file_path) as config_file_fd:
        configuration_data = yaml.safe_load(config_file_fd)

    return configuration_data


def validate_configuration_data(configuration):
    data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'data')
    schema_file = os.path.join(data_path, 'qactl_conf_validator_schema.json')

    with open(os.path.join(_data_path, schema_file), 'r') as f:
        schema = json.load(f)

    validate(instance=configuration, schema=schema)


def set_qactl_logging(qactl_configuration):
    if not qactl_configuration.logging_enable:
        qactl_logger = Logging(QACTL_LOGGER)
        qactl_logger.disable()
    else:
        qactl_logger = Logging(QACTL_LOGGER, qactl_configuration.logging_level, True, qactl_configuration.logging_file)


def validate_parameters(parameters):
    if parameters.config and parameters.run_test:
        raise ValueError('The --run parameter is incompatible with --config. --run will autogenerate the configuration')

    if parameters.dry_run and parameters.run_test is None:
        raise ValueError('The --dry-run parameter can only be used with --run')

    if parameters.version is not None:
        version = parameters.version

        if len((parameters.version).split('.')) != 3:
            raise ValueError(f"Version parameter has to be in format x.y.z. You entered {version}")

        if not version_is_released(parameters.version):
            raise ValueError(f"The wazuh {parameters.version} version has not been released. Enter a right version.")

        short_version = f"{version.split('.')[0]}.{version.split('.')[1]}"

        if not branch_exist(short_version, WAZUH_QA_REPO):
            raise ValueError(f"{short_version} branch does not exist in Wazuh QA repository.")


def main():
    parser = argparse.ArgumentParser()
    configuration_data = {}
    instance_handler = None
    configuration_file = None

    parser.add_argument('--config', '-c', type=str, action='store', required=False, dest='config',
                        help='Path to the configuration file.')

    parser.add_argument('-p', '--persistent', action='store_true',
                        help='Persistent instance mode. Do not destroy the instances once the process has finished.')

    parser.add_argument('-d', '--dry-run', action='store_true',
                        help='Config generation mode. The test data will be processed and the configuration will be ' \
                             'generated without running anything.')

    parser.add_argument('--run', '-r', type=str, action='store', required=False, nargs='+', dest='run_test',
                        help='Independent run method. Specify a test or a list of tests to be run')

    parser.add_argument('--version', '-v', type=str, action='store', required=False, dest='version',
                        help='Wazuh installation and tests version')

    arguments = parser.parse_args()

    validate_parameters(arguments)

    # Generate or get the qactl configuration file
    if arguments.run_test:
        config_generator = QACTLConfigGenerator(arguments.run_test, arguments.version)
        config_generator.run()
        configuration_file = config_generator.config_file_path

        if arguments.dry_run:
            return 0
    else:
        configuration_file = arguments.config

    # Check configuration file path exists
    assert os.path.exists(configuration_file), f"{configuration_file} file doesn't exists or could not be "\
                                                'generated correctly'

    # Read configuration data
    configuration_data = read_configuration_data(configuration_file)

    # Validate configuration schema
    validate_configuration_data(configuration_data)

    # Set QACTL configuration
    qactl_configuration = QACTLConfiguration(configuration_data)

    # Set QACTL logging
    set_qactl_logging(qactl_configuration)

    # Run QACTL modules
    # try:

    #     if arguments.version:
    #         print(f"VERSION -> {arguments.version}")

    #     if DEPLOY_KEY in configuration_data:
    #         deploy_dict = configuration_data[DEPLOY_KEY]
    #         instance_handler = QAInfraestructure(deploy_dict, qactl_configuration)
    #         instance_handler.run()
    #         launched['instance_handler'] = True
    # finally:
    #     pass
    #     if PROVISION_KEY in configuration_data:
    #         provision_dict = configuration_data[PROVISION_KEY]
    #         qa_provisioning = QAProvisioning(provision_dict, qactl_configuration)
    #         qa_provisioning.run()
    #         launched['qa_provisioning'] = True

    #     if TEST_KEY in configuration_data:
    #         test_dict = configuration_data[TEST_KEY]
    #         tests_runner = QATestRunner(test_dict, qactl_configuration)
    #         tests_runner.run()
    #         launched['test_runner'] = True

    # finally:
    #     if not arguments.persistent:
    #         print("DESTROY")
    #         if DEPLOY_KEY in configuration_data and launched['instance_handler']:
    #             instance_handler.destroy()

    #         if PROVISION_KEY in configuration_data and launched['qa_provisioning']:
    #             qa_provisioning.destroy()

    #         if TEST_KEY in configuration_data and launched['test_runner']:
    #             tests_runner.destroy()


if __name__ == '__main__':
    main()
