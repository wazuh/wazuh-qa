# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import argparse
import os
import yaml

from time import sleep
from wazuh_testing.qa_ctl.deployment.QAInfraestructure import QAInfraestructure
from wazuh_testing.qa_ctl.provisioning.QAProvisioning import QAProvisioning
from wazuh_testing.qa_ctl.run_tests.QARunTests import RunQATests
from wazuh_testing.qa_ctl.run_tests.TestLauncher import TestLauncher


DEPLOY_KEY = 'deployment'
PROVISION_KEY = 'provision'
TEST_KEY = 'tests'


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
        try:
            if DEPLOY_KEY in yaml_config:
                deploy_dict = yaml_config[DEPLOY_KEY]
                instance_handler = QAInfraestructure(deploy_dict)
                instance_handler.run()

            if PROVISION_KEY in yaml_config:
                if DEPLOY_KEY in yaml_config:
                    sleep(5)  # If machines are deployed, wait 5 seconds before connecting
                provision_dict = yaml_config[PROVISION_KEY]
                qa_provisioning = QAProvisioning(provision_dict)
                qa_provisioning.process_inventory_data()
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
