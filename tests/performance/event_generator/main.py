# Copyright (C) 2024, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
"""Main execution script for event generator system.

This script serves as the command center for initiating and managing the generation of log and file events based on user-defined configurations.

The script supports command-line arguments to specify configurations through a YAML file, facilitating complex setups with multiple event generators (log and file events). It manages concurrent event generation using threading to simulate real-world application loads and conditions.

Usage:
    python3 main.py --config <path_to_config_file>

Where:
    --config: Path to the YAML configuration file that specifies various parameters for the event generators.

This tool is ideal for testing the robustness and performance of systems that monitor or log file and system activities by simulating realistic operational loads.
"""

import argparse
import yaml
import threading
import time
import os
import shutil
from event_generator import LogEventGenerator, SyscheckEventGenerator


def delete_file(path):
    """Delete the specified file or directory."""
    try:
        if os.path.isdir(path):
            shutil.rmtree(path)
            print(f"Successfully deleted directory: {path}")
        else:
            os.remove(path)
            print(f"Successfully deleted file: {path}")
    except OSError as e:
        print(f"Error deleting {path}: {e}")


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Module saturation script.",
        usage="%(prog)s [options]",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('--config', type=str, required=True,
                        help='Path to YAML config file')
    return parser.parse_args()


def main():
    args = parse_arguments()

    with open(args.config, 'r') as file:
        config = yaml.safe_load(file)

    threads = []
    for file_config in config.get('files', []):
        # Adjust required parameters based on the module
        if file_config['module'] == 'logcollector':
            required_params = ['module', 'path', 'operations',
                               'rate', 'max_file_size', 'template_path']
        elif file_config['module'] == 'syscheck':
            required_params = ['module', 'path', 'operations', 'rate']
        else:
            raise ValueError(
                "Unsupported module specified in the configuration.")

        if not all(param in file_config for param in required_params):
            raise ValueError(
                "Missing one or more required config parameters for a file.")

        if file_config['module'] == 'logcollector':
            generator = LogEventGenerator(
                rate=file_config['rate'],
                path=file_config['path'],
                operations=file_config['operations'],
                max_file_size=file_config['max_file_size'],
                template_path=file_config['template_path']
            )
        elif file_config['module'] == 'syscheck':
            generator = SyscheckEventGenerator(
                rate=file_config['rate'],
                path=file_config['path'],
                operations=file_config['operations']
            )
        else:
            raise ValueError(
                "Unsupported module specified in the configuration.")

        thread = threading.Thread(target=generator.start)
        thread.start()
        threads.append(thread)

    # Wait for all threads to complete
    for thread in threads:
        thread.join()

    # Clean up files after all logs have been generated if specified in the configuration
    for file_config in config.get('files', []):
        # Check if cleanup flag is true for the file
        if file_config.get('cleanup', False):
            delete_file(file_config['path'])


if __name__ == "__main__":
    main()
