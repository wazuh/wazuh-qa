# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import argparse
import os
from QAInfraestructure import QAInfraestructure
import yaml

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    yaml_config = {}
    parser.add_argument('--config', '-c', type=str, action='store', required=True,
                        help='Path to the configuration file.')
    parser.add_argument('--action', '-a', type=str, action='store', required=True,
                        choices=['run', 'halt', 'status', 'info', 'destroy'],
                        help='Action to perform')

    arguments = parser.parse_args()

    assert os.path.exists(
        arguments.config), f"{arguments.config} file doesn't exists"

    with open(arguments.config) as config_file_fd:
        yaml_config = yaml.safe_load(config_file_fd)

    instance_handler = QAInfraestructure(yaml_config)

    if arguments.action == 'run':
        instance_handler.run()

    elif arguments.action == 'halt':
        instance_handler.halt()

    elif arguments.action == 'status':
        print(instance_handler.status())

    elif arguments.action == 'info':
        print(instance_handler.get_instances_info())

    elif arguments.action == 'destroy':
        instance_handler.destroy()
