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


DEPLOY_KEY = 'deployment'
PROVISION_KEY = 'provision'
TEST_KEY = 'tests'

qactl_logger = None
_data_path = os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))), 'data')


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


def main():
    parser = argparse.ArgumentParser()
    configuration_data = {}
    instance_handler = None

    parser.add_argument('--config', '-c', type=str, action='store', required=True,
                        help='Path to the configuration file.')

    parser.add_argument('--destroy', '-d', action='store_true',
                        help='Destroy the instances once the tool has finished.')

    arguments = parser.parse_args()

    # Check configuration file path exists
    assert os.path.exists(arguments.config), f"{arguments.config} file doesn't exists"

    # Read configuration data
    configuration_data = read_configuration_data(arguments.config)

    # Validate configuration schema
    validate_configuration_data(configuration_data)

    # Set QACTL configuration
    qactl_configuration = QACTLConfiguration(configuration_data)

    # Set QACTL logging
    set_qactl_logging(qactl_configuration)

    # Run QACTL modules
    try:
        if DEPLOY_KEY in configuration_data:
            deploy_dict = configuration_data[DEPLOY_KEY]
            instance_handler = QAInfraestructure(deploy_dict, qactl_configuration)
            instance_handler.run()

        if PROVISION_KEY in configuration_data:
            provision_dict = configuration_data[PROVISION_KEY]
            qa_provisioning = QAProvisioning(provision_dict, qactl_configuration)
            qa_provisioning.run()

        if TEST_KEY in configuration_data:
            test_dict = configuration_data[TEST_KEY]
            tests_runner = QATestRunner(test_dict, qactl_configuration)
            tests_runner.run()

    finally:
        if arguments.destroy:
            if DEPLOY_KEY in configuration_data:
                instance_handler.destroy()

            if PROVISION_KEY in configuration_data:
                qa_provisioning.destroy()

            if TEST_KEY in configuration_data:
                tests_runner.destroy()


if __name__ == '__main__':
    main()
