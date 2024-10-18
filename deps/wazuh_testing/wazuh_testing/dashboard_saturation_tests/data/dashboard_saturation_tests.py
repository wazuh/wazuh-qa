# Copyright (C) 2024, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or
# modify it under the terms of GPLv2

"""Dashboard Saturation Tests Module.

This script allows you to run dashboard stress tests. These tests
are performed with Artillery and Playwright. Artillery and
Playwright must be installed for it to work properly.
"""

import fnmatch
import json
import time
from argparse import ArgumentParser, Namespace, RawTextHelpFormatter
from datetime import datetime
from os import getcwd, makedirs, scandir, listdir
from os.path import isabs, join
from subprocess import run
from typing import Any

import pandas as pd
import yaml


LOGS = "logs/"
SCREENSHOTS = "screenshots/"
CSV = 'csv/'
SESSION = '.auth/'
ARTILLERY = 'data/artillery.yml'
USER = 'admin'
ITERATIONS = 1
TYPE = ['aggregate', 'intermediate']
WAIT = 5
TIMEOUT = 10000
DEBUG = False


# Global Configuration Variables
artillery_result_type = [
    # Final statistics printed to the console at the end of a test
    'aggregate',
    # Statistics that print to the console while a test is running
    'intermediate'
]


def check_artillery_result_types(types: list) -> None:
    """Check that the CSV type is valid.

    Check that the type chosen to generate the CSV with the
    Artillery results is valid.

    Args:
        types (list): List of types.
    """
    for value in types:
        if value not in artillery_result_type:
            msg = f'The Artillery result type to generate the CSV is not \
                valid. Accepted Values: {artillery_result_type}. Value \
                received {value}.'

            raise Exception(msg)


def format_directory(directory: str) -> str:
    """Check the paths of the directories and format them if necessary.

    Args:
        directory (str): Path of a directory.

    Returns:
        str: Formatted path.
    """
    return join(directory, '')


def create_directories(directory: str) -> None:
    """Create directory that does not exist.

    Args:
        directory (str): Path of directory.
    """
    makedirs(directory, exist_ok=True)


def provide_directories(args: Namespace) -> None:
    """Formatting and creating directories.

    Format directory paths to ensure they are valid and
    create such directories if they do not exist.

    Args:
        args (Namespace): Script parameters.
    """
    # Format Directories
    args.logs = format_directory(args.logs)
    args.screenshots = format_directory(args.screenshots)
    args.csv = format_directory(args.csv)
    args.session = format_directory(args.session)

    # Create Directories
    create_directories(args.logs)
    create_directories(args.screenshots)
    create_directories(args.csv)
    create_directories(args.session)


def create_session_file(path: str, user: str) -> None:
    """Create file to save the browser session.

    Args:
        path (str): Path of directory.
        user (str): Username.
    """
    file_path = f"{path}user-{user}.json"

    with open(file_path, 'w') as file:
        file.write('{}')


def gen_artillery_params(args: Namespace) -> dict:
    """Format all parameters for Artillery.

    Args:
        args (Namespace): Script parameters.

    Returns:
        dict: Artillery parameters.
    """
    artillery_params = {
        'username': args.user,
        'password': args.password,
        'screenshots': args.screenshots,
        'session': args.session,
        'timeout': args.timeout
    }

    return artillery_params


def add_options_to_artillery(config: str, options: dict) -> None:
    """Add missing parameters to Artillery config.

    Args:
        config (str): YAML de Artillery.
        options (dict): Parametros de Artillery.
    """
    # Open YML
    with open(config) as f:
        data = yaml.safe_load(f)

    # Check `config` in Artillery YAML
    if 'config' not in data.keys():
        data['config'] = {}

    # Check `variables` in Artillery YAML
    if 'variables' not in data['config'].keys():
        data['config']['variables'] = {}

    # Add Options to Artillery
    for key in options:
        if key not in data['config']['variables'].keys():
            data['config']['variables'][key] = f'{{{{ { key } }}}}'

    # Save YML
    with open(config, "w") as f:
        yaml.dump(data, f)


def process_script_arguments(args: Namespace) -> None:
    """Process script arguments, create folders and generate necessary files.

    Args:
        args (Namespace): Script parameters.
    """
    # Format .auth Path
    if not isabs(args.session):
        args.session = f'{getcwd()}/{args.session}'

    # Check Artillery Result Types
    check_artillery_result_types(args.type)

    # Provide Necessary Directories
    provide_directories(args)

    # Create Session File
    create_session_file(args.session, args.user)

    # Check Artillery Parameters
    add_options_to_artillery(args.artillery, gen_artillery_params(args))


def gen_log_filename(log_path: str) -> str:
    """Generate log file name.

    Args:
        log_path (str): Path of the logs.

    Returns:
        str: File name of the log (include path).
    """
    return log_path + datetime.now().strftime("log-%Y%m%d%H%M%S.json")


def gen_url(ip: str) -> str:
    """Generate dashboard url.

    Args:
        ip (str): IP of the dashboard.

    Returns:
        str: Complete url of the dashboard.
    """
    url_format = 'https://'

    return f'{url_format}{ip}'


def gen_csv_filename(csv_path: str, type: str, entry: str = None) -> str:
    """Generate csv file name (per type).

    Args:
        csv_path (str): Path of the CSVs.
        type (str): CSV data type.
        entry (str): Log Entry.

    Returns:
        str: File name of the csv (include type and path).
    """
    return csv_path + datetime.now().strftime(f"{type}_{entry}_%Y%m%d%H%M%S.csv")


def merge_dictionaries(list_of_dicts: list[dict[str, Any]]) -> dict[str, Any]:
    """Merge a list of dictionaries into a single dictionary.

    Args:
        list_of_dicts (str): list of dictionaries.

    Returns:
        dict: Dictionary with merged data.
    """
    combined_dict = {
        'counters': {},
        'summaries': {},
        'histograms': {},
    }

    keys_to_merge = ['counters', 'summaries', 'histograms']

    for item in list_of_dicts:
        for key in keys_to_merge:
            if key in item:
                if key in combined_dict:
                    combined_dict[key].update(item[key])
                else:
                    combined_dict[key] = item[key]

    return combined_dict


def convert_json_to_csv(args: Namespace, json_output: str) -> None:
    """Convert data from JSON format to CSV format.

    Args:
        args (Namespace): Script parameters.
        json_output (str): Path and file name of the log.
    """
    keys = ['counters', 'summaries', 'histograms']

    with open(json_output) as f:
        data = json.load(f)

    for type in args.type:
        filtered_data = data[type]

        if isinstance(filtered_data, list):
            filtered_data = merge_dictionaries(filtered_data)

        for key in keys:
            csv_filename = gen_csv_filename(args.csv, type, key)
            df = pd.json_normalize(filtered_data[key])
            df.to_csv(csv_filename, index=False)


def run_artillery(args: Namespace) -> None:
    """Execute Artillery tests.

    Args:
        args (Namespace): Script parameters.
    """
    json_filename = gen_log_filename(args.logs)

    params = f"-v '{json.dumps(gen_artillery_params(args))}'"
    target = f"-t {gen_url(args.ip)}"

    # Enable Quiet Mode (Artillery)
    quiet = ''

    if not args.debug:
        quiet = '-q'

    output = f"-o {json_filename}"
    script = f"{args.artillery}"

    command = f'artillery run {params} {target} {quiet} {output} {script}'

    run(command, shell=True)

    if any(scandir(args.logs)):
        convert_json_to_csv(args, json_filename)


def merge_csv(args: Namespace) -> None:
    """Merge multiple CSV files into one.

    Args:
        args (Namespace): Script parameters.
    """
    for type in args.type:
        keys = ['counters', 'summaries', 'histograms']

        for key in keys:
            pattern = f'{type}_{key}*'
            files = fnmatch.filter(listdir(args.csv), pattern)

            if len(files) > 1:
                data_frames = []

                for file in files:
                    df = pd.read_csv(join(args.csv, file))
                    data_frames.append(df)

                combined_df = pd.concat(data_frames)
                filename = gen_csv_filename(args.csv, f'combined_{type}', key)
                combined_df.to_csv(filename, index=False)


def get_script_arguments() -> Namespace:
    """Add and Receive the Script Parameters.

    Returns:
        Namespace: Script parameters.
    """
    parser = ArgumentParser(
        usage='%(prog)s [options]',
        description='Script to Run Dashboard Saturation Tests',
        formatter_class=RawTextHelpFormatter
    )

    parser.add_argument(
        '-l', '--log',
        dest='logs',
        type=str,
        default=LOGS,
        help=f'Directory to store the logs. Default {LOGS}.'
    )

    parser.add_argument(
        '-s', '--screenshots',
        dest='screenshots',
        type=str,
        default=SCREENSHOTS,
        help=f'Directory to store the screenshots. Default {SCREENSHOTS}.'
    )

    parser.add_argument(
        '-c', '--csv',
        dest='csv',
        type=str,
        default=CSV,
        help=f'Directory to store the CSVs. Default {CSV}.'
    )

    parser.add_argument(
        '-o', '--session',
        dest='session',
        type=str,
        default=SESSION,
        help=f'Directory to store the Sessions. Default {SESSION}.'
    )

    parser.add_argument(
        '-a', '--artillery',
        dest='artillery',
        type=str,
        default=ARTILLERY,
        help=f'Path to the Artillery Script. Default {ARTILLERY}.'
    )

    parser.add_argument(
        '-u', '--user',
        dest='user',
        type=str,
        default=USER,
        help=f'Wazuh User for the Dashboard. Default {USER}.'
    )

    parser.add_argument(
        '-p', '--password',
        dest='password',
        type=str,
        required=True,
        help='Wazuh Password for the Dashboard.'
    )

    parser.add_argument(
        '-q', '--iterations',
        dest='iterations',
        type=int,
        default=ITERATIONS,
        help=f'Number of Tests to Run. Default {ITERATIONS}.'
    )

    parser.add_argument(
        '-i', '--ip',
        dest='ip',
        type=str,
        required=True,
        help='Set the Dashboard IP.'
    )

    parser.add_argument(
        '-t', '--type',
        dest='type',
        type=str,
        nargs='+',
        action='store',
        default=TYPE,
        help=f'JSON data to create the CSV. Default {TYPE}'
    )

    parser.add_argument(
        '-w', '--wait',
        dest='wait',
        type=int,
        default=WAIT,
        help=f'Waiting Time between Executions. Default {WAIT}'
    )

    parser.add_argument(
        '-m', '--timeout',
        dest='timeout',
        type=int,
        default=TIMEOUT,
        help=f'Timeout in milliseconds. Default {TIMEOUT}.'
    )

    parser.add_argument(
        '-d', '--debug',
        dest='debug',
        action='store_true',
        required=False,
        default=DEBUG,
        help=f'Enable Debug Mode. Default {DEBUG}'
    )

    return parser.parse_args()


def main() -> None:
    """Run the Script."""
    script_args = get_script_arguments()

    process_script_arguments(script_args)

    for _ in range(0, script_args.iterations):
        run_artillery(script_args)
        time.sleep(script_args.wait)

    merge_csv(script_args)


if __name__ == "__main__":
    main()
