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
from wazuh_testing.qa_ctl.run_tests.qa_run_tests import RunQATests
from wazuh_testing.qa_ctl.run_tests.test_launcher import TestLauncher


DEPLOY_KEY = 'deployment'
PROVISION_KEY = 'provision'
TEST_KEY = 'tests'
_data_path = os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))), 'data')


def validate_conf(configuration):
    schema_file = 'qactl_conf_validator_schema.json'

    with open(os.path.join(_data_path, schema_file), 'r') as f:
        schema = json.load(f)

    validate(instance=configuration, schema=schema)


def main():
    parser = argparse.ArgumentParser()
    yaml_config = {}
    instance_handler = None

    parser.add_argument('--config', '-c', type=str, action='store', required=True,
                        help='Path to the configuration file.')

    parser.add_argument('--destroy', '-d', action='store_true',
                        help='Destroy the instances once the tool has finished.')

    arguments = parser.parse_args()

    assert os.path.exists(arguments.config), f"{arguments.config} file doesn't exists"

    with open(arguments.config) as config_file_fd:
        yaml_config = yaml.safe_load(config_file_fd)
        validate_conf(yaml_config)
        
    try:
        if DEPLOY_KEY in yaml_config:
            deploy_dict = yaml_config[DEPLOY_KEY]
            instance_handler = QAInfraestructure(deploy_dict)
            instance_handler.run()

        if PROVISION_KEY in yaml_config:
            provision_dict = yaml_config[PROVISION_KEY]
            qa_provisioning = QAProvisioning(provision_dict)
            qa_provisioning.process_inventory_data()
            qa_provisioning.check_hosts_connection()
            qa_provisioning.process_deployment_data()

        if TEST_KEY in yaml_config:
            test_dict = yaml_config[TEST_KEY]
            tests_runner = RunQATests(test_dict)
            test_launcher = TestLauncher(tests_runner.tests, tests_runner.inventory_file_path)
            test_launcher.run()

    finally:
        if arguments.destroy:
            instance_handler.destroy()


if __name__ == '__main__':
    main()
