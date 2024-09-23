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

from event_generator import EventGenerator, LogEventGenerator, SyscheckEventGenerator


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


def create_event_generator(file_config: dict[str, Any]) -> EventGenerator:
    """Create and return an EventGenerator instance based on the provided file configuration.

    Args:
        file_config (dict): Configuration settings specific to the module.

    Returns:
        EventGenerator: An instance of the appropriate EventGenerator subclass.

    Raises:
        ValueError: If any required parameters are missing or if the module is unsupported.
    """
    module = file_config.get('module')
    if not module:
        raise ValueError("Missing 'module' parameter in configuration.")

    # Mapping of module names to their classes and parameters
    module_mapping = {
        'logcollector': {
            'class': LogEventGenerator,
            'required_params': ['path', 'operations', 'rate'],
            'optional_params': ['max_file_size', 'template_path', 'max_retries'],
        },
        'syscheck': {
            'class': SyscheckEventGenerator,
            'required_params': ['path', 'rate', 'num_files', 'num_modifications'],
            'optional_params': ['max_retries'],
        },
    }

    if module not in module_mapping:
        raise ValueError(f"Unsupported module specified in the configuration: {module}")

    module_info = module_mapping[module]
    generator_class = module_info['class']
    required_params = module_info['required_params']
    optional_params = module_info.get('optional_params', [])

    # Validate required parameters
    missing_params = [param for param in required_params if param not in file_config]
    if missing_params:
        raise ValueError(f"Missing required config parameters for {module}: {', '.join(missing_params)}")

    # Prepare arguments for the generator class
    init_args = {param: file_config[param] for param in required_params}
    # Include optional parameters if they are provided
    init_args.update({param: file_config[param] for param in optional_params if param in file_config})

    # Handle module-specific logic
    if module == 'syscheck':
        num_files = init_args['num_files']
        num_modifications = init_args['num_modifications']
        # Calculate total operations: create + (modify * num_modifications) + delete
        operations = num_files + (num_files * num_modifications) + num_files
        init_args['operations'] = operations
    elif module == 'logcollector':
        # For logcollector, operations are provided directly
        pass

    return generator_class(**init_args)


def main() -> None:
    """Main function to parse arguments and initiate event generation based on configurations."""
    args = parse_arguments()

    with open(args.config) as file:
        config = yaml.safe_load(file)

    threads = []
    for file_config in config.get('files', []):
        try:
            generator = create_event_generator(file_config)
        except ValueError as e:
            logging.error(f"Error creating event generator: {e}")
            continue

        thread = threading.Thread(target=generator.start)
        threads.append(thread)

    # Now, start all threads after processing is complete
    for thread in threads:
        thread.start()

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
