import argparse
import json
import pandas as pd

from datetime import datetime
from os import makedirs
from os.path import exists
from subprocess import run

# Global Configuration Variables
csv_types = ['aggregate', 'intermediate']
url_format = 'https://'

def format_directory(directory):
    """Check the paths of the directories and format them if necessary.
    Args:
        args (string): Path of a directory.
    Returns:
        string: Formatted path.
    """
    return directory if directory.endswith("/") else f'{directory}/'

def check_csv_types(types):
    """Check that the CSV type is valid.
    Args:
        types (list): List of types.
    """
    for value in types:
        if (value not in csv_types):
            raise Exception("CSV type is not valid") 
        
def create_directories(directory):
    """Create directory that does not exist.
    Args:
        directory (str): Path of directory.
    """
    if not exists(directory):
        makedirs(directory)

def create_session_file(path, user):
    """Create file to save the browser session.
    Args:
        path (str): Path of directory.
        user (str): Username.
    """
    file_path = f"{path}user-{user}.json"

    with open(file_path, 'w') as file:
        file.write('{}')

def process_script_arguments(args):
    """Process script arguments, create folders and generate necessary files.
    Args:
        args (ArgumentParser): Script parameters.
    """
    # Format Directories
    args.logs = format_directory(args.logs)
    args.screenshots = format_directory(args.screenshots)
    args.csv = format_directory(args.csv)
    args.session = format_directory(args.session)

    # Check CSV Types
    check_csv_types(args.type)

    # Create Directories
    create_directories(args.logs)
    create_directories(args.screenshots)
    create_directories(args.csv)
    create_directories(args.session)

    # Create Session File
    create_session_file(args.session, args.user)

def format_artillery_params(key, value):
    """Format options for Artillery.
    Args:
        key (str): Name of the Artillery option.
        value (str): Value of the Artillery option.
    Returns:
        str: Formatted Artillery option.
    """
    return f"\"{key}\": \"{value}\""

def gen_artillery_params(args):
    """Format all parameters for Artillery.
    Args:
        args (ArgumentParser): Script parameters.
    Returns:
        str: Formatted Artillery parameters.
    """
    user = format_artillery_params('username', args.user)
    password = format_artillery_params('password', args.password)
    screenshots = format_artillery_params('screenshots', args.screenshots)
    session = format_artillery_params('session', args.session)

    params = f"\'{{{user}, {password}, {screenshots}, {session}}}\'"

    return params

def gen_log_filename(log_path):
    """Generate log file name.
    Args:
        log_path (str): Path of the logs.
    Returns:
        str: File name of the log (include path).
    """
    return log_path + datetime.now().strftime(f"log-%Y%m%d%H%M%S.log")

def gen_url(ip):
    """Generate dashboard url.
    Args:
        ip (str): IP of the dashboard.
    Returns:
        str: Complete url of the dashboard.
    """
    return f'{url_format}{ip}'

def gen_csv_filename(csv_path, type):
    """Generate csv file name (per type).
    Args:
        csv_path (str): Path of the CSVs.
        type (str): CSV data type.
    Returns:
        str: File name of the csv (include type and path).
    """
    return csv_path + datetime.now().strftime(f"{type}-%Y%m%d%H%M%S.csv")

def convert_json_to_csv(args, json_output):
    """Convert data from JSON format to CSV format.
    Args:
        args (ArgumentParser): Script parameters.
        json_output (str): Path and file name of the log.
    """
    for type in args.type:
        with open(json_output) as f:
            data = json.load(f)

        csv_filename = gen_csv_filename(args.csv, type)

        df = pd.json_normalize(data[type])
        df.to_csv(csv_filename, index=False)

def run_artillery(args):
    """Execute Artillery tests.
    Args:
        args (ArgumentParser): Script parameters.
    """
    json_filename = gen_log_filename(args.logs)

    params = f"-v {gen_artillery_params(args)}"
    target = f"-t {gen_url(args.ip)}"

    # Enable Quiet Mode (Artillery)
    quiet = ''

    if not args.debug:
        quiet = f"-q"

    output = f"-o {json_filename}"
    script = f'{args.artillery}'

    command = f"artillery run {params} {target} {quiet} {output} {script}"

    run(command, shell=True)
    convert_json_to_csv(args, json_filename)

def get_script_arguments():
    parser = argparse.ArgumentParser(usage='%(prog)s [options]', 
                                     description='Script to Run Dashboard Saturation Tests',
                                     formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument('-l', '--logs', dest='logs', default='logs/',
                        help=f'Directory to store the logs. Default "logs".')
    
    parser.add_argument('-s', '--screenshots', dest='screenshots', default='screenshots/',
                        help=f'Directory to store the screenshots. Default "screenshot".')
    
    parser.add_argument('-c', '--csv', dest='csv', default='csv/',
                        help=f'Directory to store the CSVs. Default "csv".')

    parser.add_argument('-o', '--session', dest='session', default='.auth/',
                        help=f'Directory to store the Sessions. Default ".auth".')

    parser.add_argument('-a', '--artillery', dest='artillery', type=str, default="artillery.yml",
                        help=f'Path to the Artillery Script. Default "artillery.yml".')

    parser.add_argument('-u', '--user', dest='user', type=str, default= 'admin',
                        help=f'Wazuh User for the Dashboard. Default "admin".')

    parser.add_argument('-p', '--password', dest='password', type=str, required=True,
                        help=f'Wazuh Password for the Dashboard.')
    
    parser.add_argument('-q', '--quantity', dest='quantity', type=int, default=1,
                        help=f'Number of Tests to Run. Default {1}')
    
    parser.add_argument('-i', '--ip', dest='ip', type=str, required=True,
                        help=f'Set the Dashboard IP.')

    parser.add_argument('-t', '--type', dest='type', type=str, nargs='+', action='store',
                        default=['aggregate', 'intermediate'],
                        help=f'JSON data to create the CSV.')
    
    parser.add_argument('-d', '--debug', dest='debug', action='store_true', required=False,
                        default=False, help='Enable debug mode')

    return parser.parse_args()

def main():
    script_args = get_script_arguments()

    process_script_arguments(script_args)

    for n in range(0, script_args.quantity):    
        run_artillery(script_args)

if __name__ == "__main__":
    main()