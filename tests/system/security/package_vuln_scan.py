import re
import subprocess
from argparse import ArgumentParser
from collections import namedtuple
from datetime import datetime
from json import dumps, loads

from safety.formatter import report
from safety.safety import check

python_bin = subprocess.run(['which', 'python3'], stdout=subprocess.PIPE, universal_newlines=True).stdout.strip()
package_list = []
package_tuple = namedtuple('Package', ['key', 'version'])


def get_args():
    """Command line argument parsing method

    Returns:
        Namespace(args*): Optional and Positional Parsing
    """
    parser = ArgumentParser()
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('-r', dest='input', type=str, help='specify requirements file path.')
    input_group.add_argument('-p', dest='pip_mode', action='store_true', help='enable pip scan mode.')
    parser.add_argument('-o', dest='output', type=str, help='specify output file.')
    return parser.parse_args()


def run_report(output_file_path):
    """Perform vulnerability scan using Safety to check all packages listed.

    Args:
        output_file_path (str): file path where results will be saved.
    """
    json_report = []
    vulns = check(packages=package_list, key='', db_mirror='', cached=False, ignore_ids=(), proxy={})
    output_report = report(vulns=vulns, full=True, json_report=True, bare_report=False,
                           checked_packages=len(package_list), db='', key='')
    for package_information in loads(output_report):
        json_report.append({
            'package_name': package_information[0],
            'package_version': package_information[2],
            'package_affected_version': package_information[1],
            'vuln_description': package_information[3],
            'safety_id': package_information[4]
        })
    json_data = {
        'report_date': datetime.now().isoformat(),
        'vulnerabilities_found': len(json_report),
        'packages': json_report
    }
    if output_file_path:
        with open(output_file_path, mode='w') as output_file:
            output_file.write(dumps(json_data, indent=4))
    else:
        print(dumps(json_data, indent=4))


def prepare_input(pip_mode, input_file_path):
    """Create temp input file with all packages listed and prepared to be scanned later on.

    Args:
        pip_mode (bool): enable/disable pip freeze to retrieve package information.
        input_file_path (str): path to the input file (used if pip_mode is disabled).
    """
    python_process = subprocess.run([python_bin, '--version'], stdout=subprocess.PIPE, universal_newlines=True)
    aux = python_process.stdout.strip().split()
    package_list.append(package_tuple(aux[0], aux[1]))
    if pip_mode:
        pip_mode_pocess = subprocess.run([python_bin, '-m', 'pip', 'freeze'], stdout=subprocess.PIPE,
                                         universal_newlines=True)
        for package_line in pip_mode_pocess.stdout.strip().split('\n'):
            aux = package_line.strip().split('==')
            package_list.append(package_tuple(aux[0], aux[1]))
    else:
        with open(input_file_path, mode='r') as input_file:
            lines = input_file.readlines()
            for line in lines:
                line = re.sub('[<>~]', '=', line)
                if ',' in line:
                    package_version = max(re.findall('\d+\.+\d*\.*\d', line))
                    package_name = re.findall('([a-z]+)', line)[0]
                    line = f'{package_name}=={package_version}\n'
                if ';' in line:
                    line = line.split(';')[0] + '\n'
                aux = line.strip().split('==')
                package_list.append(package_tuple(aux[0], aux[1]))


if __name__ == '__main__':
    options = get_args()
    opt_pip_mode = options.pip_mode
    opt_output_file_path = options.output
    opt_input_file_path = options.input

    prepare_input(opt_pip_mode, opt_input_file_path)
    run_report(opt_output_file_path)
