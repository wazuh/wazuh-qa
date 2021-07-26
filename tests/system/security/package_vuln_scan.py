import argparse
import subprocess
import json
import re
import os
from datetime import datetime

INPUT_FILE_PATH_TMP = 'input_file_tmp.txt'


def get_args():
    """
    Summary:
        Command line argument parsing method.
    """
    parser = argparse.ArgumentParser()
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('-r', dest='input', type=str,
                             help='specify requirements file path.')
    input_group.add_argument('-p', dest='pip_mode', action='store_true',
                             help='enable pip scan mode.')
    parser.add_argument('-o', dest='output', type=str, required=True,
                        help='specify output file.')
    return parser.parse_args()


def run_report(output_file_path, input_file_path):
    """
    Summary:
        Perform vulnerability scan using Safety to check all packages listed.
    Args:
        output_file_path ([str]): file path where results will be saved.
        input_file_path ([str]): file path where packages are listed.
    """
    json_report = []
    json_data = []
    safety_process = subprocess.run(['safety',
                                     'check',
                                     '--json',
                                     '-r',
                                     input_file_path],
                                    stdout=subprocess.PIPE,
                                    universal_newlines=True)
    for package_information in json.loads(safety_process.stdout):
        json_report.append({
            'package_name': package_information[0],
            'package_version': package_information[2],
            'package_affected_version': package_information[1],
            'vuln_description': package_information[3],
            'safety_id': package_information[4]
        })
    json_data = {
        'report_date': datetime.now().strftime('%d/%m/%Y - %H:%M:%S'),
        'vulnerabilities_found': len(json_report),
        'packages': json_report
    }
    with open(output_file_path, mode='w') as output_file:
        output_file.write(json.dumps(json_data, indent=4))


def prepare_input(pip_mode, input_file_path):
    """
    Summary:
        Create temp input file with all packages listed and prepared to be scanned later on.
    Args:
        pip_mode ([bool]): enable/disable pip freeze to retrieve package information.
        input_file_path ([str]): path to the input file (used if pip_mode is disabled).
    """
    with open(INPUT_FILE_PATH_TMP, mode='a') as input_file_tmp:
        python_process = subprocess.run(['python',
                                        '--version'],
                                        stdout=subprocess.PIPE,
                                        universal_newlines=True)
        python = python_process.stdout.replace(' ', '==')
        input_file_tmp.write(python)
        if pip_mode:
            subprocess.run(['pip', 'freeze'], stdout=input_file_tmp, universal_newlines=True)
        else:
            with open(input_file_path, mode='r') as input_file:
                lines = input_file.readlines()
                tmp = ''
                for line in lines:
                    line = re.sub('[<|>|~]', '=', line)
                    if ',' in line:
                        package_version = max(re.findall('[0-9]+[.]+[0-9]*[.]*[0-9]', line))
                        package_name = re.findall('([a-z]+)', line)[0]
                        line = f'{package_name}=={package_version}\n'
                    if ';' in line:
                        line = line.split(';')[0] + '\n'
                    tmp = tmp + line
                input_file_tmp.write(tmp)


def cleanup():
    """
    Summary:
        Clean temporal files.
    """
    os.remove(INPUT_FILE_PATH_TMP)


if __name__ == '__main__':
    options = get_args()
    pip_mode = options.pip_mode
    output_file_path = options.output
    input_file_path = options.input

    prepare_input(pip_mode, input_file_path)
    run_report(output_file_path, INPUT_FILE_PATH_TMP)
    cleanup()
