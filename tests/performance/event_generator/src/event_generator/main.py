# Copyright (C) 2024, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
"""Main execution script for event generator system.

This script serves as the command center for initiating and managing the
generation of log and file events based on user-defined configurations.

The script supports command-line arguments to specify configurations through a YAML file,
facilitating complex setups with multiple event generators (log and file events).
It manages concurrent event generation using threading to simulate real-world
application loads and conditions.

Usage:
    python3 main.py --config <path_to_config_file>

Where:
    --config: Path to the YAML configuration file that specifies various
              parameters for the event generators.

This tool is ideal for testing the robustness and performance of systems that
monitor or log file and system activities by simulating realistic operational loads.
"""

import argparse
import logging
import os
import shutil
import threading
from typing import Any

import yaml

from event_generator import LogEventGenerator, SyscheckEventGenerator


def delete_file(path: str) -> None:
    """Delete the specified file or directory."""
    try:
        if os.path.isdir(path):
            shutil.rmtree(path)
            logging.info(f"Successfully deleted directory: {path}")
        else:
            os.remove(path)
            logging.info(f"Successfully deleted file: {path}")
    except OSError as e:
        logging.error(f"Error deleting {path}: {e}")


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments using argparse and validate them.

    This function sets up an argparse.ArgumentParser to read command line
    arguments. It specifically looks for a '--config' argument which is mandatory.
    It then validates these arguments using the validate_parameters function.

    Returns:
        argparse.Namespace: An object containing attributes that correspond to
            the parsed arguments. This object will specifically contain 'config'
            which holds the path to a YAML configuration file.

    Raises:
        ValueError: If the arguments fail validation checks within the
            validate_parameters function.
    """
    parser = argparse.ArgumentParser(
        description="Module saturation script.",
        usage="%(prog)s [options]",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('--config', type=str, required=True,
                        help='Path to YAML config file')
    args = parser.parse_args()

    validate_parameters(args)

    return args


def validate_parameters(args: argparse.Namespace) -> None:
    """Validate the command line arguments provided.

    Args:
        args (argparse.Namespace): The arguments provided to the command line.

    Raises:
        ValueError: If any required arguments are missing or invalid.

    Ensures that the 'config' argument is provided and that it points to a valid file.
    """
    if not args.config:
        raise ValueError("Configuration file must be provided.")
    if not os.path.isfile(args.config):
        raise ValueError("Invalid configuration file.")


def get_logcollector_generator(file_config: dict[str, Any]) -> LogEventGenerator:
    """Create and return a LogEventGenerator instance configured according to the provided file configuration.

    Args:
        file_config (dict): Configuration settings specific to the logcollector module. It must include
                            necessary parameters like module, path, operations, rate, max_file size, and
                            template path.

    Returns:
        LogEventGenerator: An instance of LogEventGenerator configured as per the file_config.

    Raises:
        ValueError: If any required parameters are missing in file_config for logcollector.
    """
    required_params = ['module', 'path', 'operations',
                       'rate', 'max_file_size', 'template_path']
    if not all(param in file_config for param in required_params):
        raise ValueError(
            "Missing required config parameters for logcollector.")
    return LogEventGenerator(
        rate=file_config['rate'],
        path=file_config['path'],
        operations=file_config['operations'],
        max_file_size=file_config['max_file_size'],
        template_path=file_config['template_path']
    )


def get_syscheck_generator(file_config: dict[str, Any]) -> SyscheckEventGenerator:
    """Create and return a SyscheckEventGenerator instance based on the provided file configuration.

    Args:
        file_config (dict): Configuration settings specific to the syscheck module. It should include necessary
                            parameters like module, path, operations, rate, num_files and num_modifications.

    Returns:
        SyscheckEventGenerator: An instance of SyscheckEventGenerator configured according to the file_config.

    Raises:
        ValueError: If any required parameters are missing in file_config for syscheck.
    """
    required_params = ['module', 'path', 'rate', 'num_files', 'num_modifications']
    if not all(param in file_config for param in required_params):
        raise ValueError("Missing required config parameters for syscheck.")

    num_files = file_config['num_files']
    num_modifications = file_config['num_modifications']

    # Calculate total operations: create + (modify * num_modifications) + delete
    operations = num_files + (num_files * num_modifications) + num_files

    return SyscheckEventGenerator(
        rate=file_config['rate'],
        path=file_config['path'],
        operations=operations,
        num_files=num_files,
        num_modifications=num_modifications
    )


def main() -> None:
    """Main function to parse arguments and initiate event generation based on configurations."""
    args = parse_arguments()

    with open(args.config) as file:
        config = yaml.safe_load(file)

    threads = []
    for file_config in config.get('files', []):
        if file_config['module'] == 'logcollector':
            generator = get_logcollector_generator(file_config)
        elif file_config['module'] == 'syscheck':
            generator = get_syscheck_generator(file_config)
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