# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import argparse
import os
from wazuh_testing.qa_ctl.deployment.QAInfraestructure import QAInfraestructure
from wazuh_testing.qa_ctl.provisioning.QAProvisioning import QAProvisioning
from wazuh_testing.qa_ctl.run_tests.QARunTests import RunQATests
from wazuh_testing.qa_ctl.run_tests.TestLauncher import TestLauncher
import yaml

DEPLOY_KEY = 'deployment'
PROVISION_KEY = 'provision'
TEST_KEY = 'tests'


def main():
    parser = argparse.ArgumentParser()
    yaml_config = {}
    instance_handler = None

    parser.add_argument('--config', '-c', type=str, action='store', required=True,
                        help='Path to the configuration file.')

    arguments = parser.parse_args()

    assert os.path.exists(arguments.config), f"{arguments.config} file doesn't exists"

    with open(arguments.config) as config_file_fd:
        yaml_config = yaml.safe_load(config_file_fd)

        if DEPLOY_KEY in yaml_config:
            deploy_dict = yaml_config[DEPLOY_KEY]
            instance_handler = QAInfraestructure(deploy_dict)
            instance_handler.run()
            print(instance_handler.get_instances_info())

        if PROVISION_KEY in yaml_config:
            provision_dict = yaml_config[PROVISION_KEY]
            qa_provisioning = QAProvisioning(provision_dict)
            qa_provisioning.process_inventory_data()
            qa_provisioning.process_deployment_data()

        if TEST_KEY in yaml_config:
            test_dict = yaml_config[TEST_KEY]
            qa_test = RunQATests(test_dict)
            test_launcher = TestLauncher(tests=qa_test.tests)
            test_launcher.run()


if __name__ == '__main__':
    main()
