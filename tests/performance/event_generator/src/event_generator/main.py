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

from event_generator import EventGenerator, LogEventGenerator, SyscheckEventGenerator, EventGeneratorFactory


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


def main() -> None:
    """Main function to parse arguments and initiate event generation based on configurations."""
    args = parse_arguments()

    with open(args.config) as file:
        config = yaml.safe_load(file)

    threads = []
    generators_info = []

    for file_config in config.get('files', []):
        # Make a copy of file_config to avoid modifying the original
        config_copy = file_config.copy()

        try:
            module_name = config_copy.pop('module')
            cleanup = config_copy.pop('cleanup', False)
            path = config_copy.get('path')
            generator = EventGeneratorFactory.create_event_generator(module_name, config_copy)

            generators_info.append({
                'generator': generator,
                'cleanup': cleanup,
                'path': path,
                'module': module_name
            })
        except ValueError as e:
            logging.error(f"Error creating event generator: {e}")
            continue

    # Start all generators
    for info in generators_info:
        thread = threading.Thread(target=info['generator'].start)
        threads.append(thread)

    # Start all threads
    for thread in threads:
        thread.start()

    # Wait for all threads to complete
    for thread in threads:
        thread.join()

    # Perform cleanup if needed
    for info in generators_info:
        if info['cleanup']:
            delete_file(info['path'])


if __name__ == "__main__":
    main()
