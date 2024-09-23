# Copyright (C) 2024, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

"""Data Visualization Script.

This script executes the data visualization module using a Dash application. In addition, it contains some functions
to process the YAML configuration file that is passed as an argument to the script. This file must contain the type
of component to be displayed (agent, manager, dashboard or indexer), the processes to be displayed depending on the
component ( for example, daemons) and the columns of the CSV files that are not to be displayed (for example, commit
or version).
"""

import os
from typing import Any, Dict

import yaml
from argparse import ArgumentParser, Namespace, RawTextHelpFormatter
from cache import cache
from dash import Dash
from callbacks import callbacks
from layout import create_layout


def load_config(config_file: str) -> Dict[str, Any]:
    """Function for loading the file containing the configuration items for visualization in YAML format.

    Args:
        config_file (str): file containing configuration items.

    Returns:
        config (Dict[str, Any]): dictionary containing information from the YAML file.
    """
    with open(config_file) as file:
        config = yaml.safe_load(file)
    return config


def get_arguments() -> Namespace:
    """Function that receives and returns the script parameters.

    Returns:
        (Namespace): script arguments.
    """
    parser = ArgumentParser(
        usage='%(prog)s [config_file]',
        description='Script to Run Data Visualization Module',
        formatter_class=RawTextHelpFormatter
    )

    parser.add_argument(
        '--config',
        dest='config',
        type=str,
        default=None,
        help='YAML file containing configuration items'
    )

    return parser.parse_args()


def process_argument(args: Namespace) -> Dict[str, Any]:
    """Function that checks the existence of the YAML file and returns its configuration in a dictionary.

    Args:
        args (Namespace): scripts arguments.

    Returns:
        (Dict[str, Any]): dictionary containing information from the YAML file.
    """
    config_file = args.config
    if not config_file or not os.path.exists(config_file):
        raise ValueError("The YAML file does not exit.")
    else:
        return load_config(config_file)


def main() -> None:
    """Main function that executes the script."""
    # Process argument (YAML file)
    args = get_arguments()
    config = process_argument(args)

    # Initialize the Dash app
    app = Dash(__name__, suppress_callback_exceptions=True)

    # Initialize the cache
    cache.init_app(app.server)

    # Set the layout of the app
    app.layout = create_layout(config)

    # Register callbacks
    callbacks(app, config)

    # Run app
    app.run_server(debug=True)


if __name__ == '__main__':
    main()
