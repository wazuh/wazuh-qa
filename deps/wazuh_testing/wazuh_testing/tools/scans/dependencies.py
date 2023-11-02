# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import re
import subprocess
from collections import namedtuple
from datetime import datetime
from os import environ

from safety.formatter import report
from safety.safety import check

python_bin = environ['_']
package_list = []
package_tuple = namedtuple('Package', ['key', 'version'])


def run_report():
    """Perform vulnerability scan using Safety to check all packages listed.

    Returns:
        dict: information about packages and vulnerabilities.
    """
    json_report = []
    vulns = check(packages=package_list, key='', db_mirror='', cached=False, ignore_ids=(), proxy={})
    output_report = report(vulns=vulns, full=True, json_report=True, bare_report=False,
                           checked_packages=len(package_list), db='', key='')
    for package_information in json.loads(output_report):
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
    return json_data


def prepare_input(pip_mode, input_file_path):
    """Create temp input file with all packages listed and prepared to be scanned later on.

    Args:
        pip_mode (bool): enable/disable pip freeze to retrieve package information.
        input_file_path (str): path to the input file (used if pip_mode is disabled).
    """
    python_process = subprocess.run([python_bin, '--version'], stdout=subprocess.PIPE, universal_newlines=True)
    pkg = python_process.stdout.strip().split()
    package_list.append(package_tuple(pkg[0], pkg[1]))
    if pip_mode:
        pip_mode_process = subprocess.run([python_bin, '-m', 'pip', 'freeze'], stdout=subprocess.PIPE,
                                          universal_newlines=True)
        for package_line in pip_mode_process.stdout.strip().split('\n'):
            pkg = package_line.strip().split('==')
            package_list.append(package_tuple(pkg[0], pkg[1]))
    else:
        with open(input_file_path, mode='r') as input_file:
            lines = input_file.readlines()
            for line in lines:
                if line.strip().startswith('#') or not line.strip():
                    continue
                line = re.sub('[<>~]', '=', line)
                if ',' in line:
                    package_version = max(re.findall(r'\d+\.+\d*\.*\d', line))
                    package_name = re.findall('([a-z]+)', line)[0]
                    line = f'{package_name}=={package_version}\n'
                if ';' in line:
                    line = line.split(';')[0] + '\n'
                pkg = line.strip().split('==')
                package_list.append(package_tuple(pkg[0], pkg[1]))


def export_report(output, output_file_path):
    """Export report to a file or console as a message.

    Args:
        output (str): information about packages and vulnerabilities.
        output_file_path (str): path to file.
    """
    if output_file_path:
        with open(output_file_path, mode='w') as output_file:
            output_file.write(output)
    else:
        print(output)


def read_known_flaws(known_flaws_path):
    """Read flaws detected by Safety in previous scans.

    Args:
        known_flaws_path (str): string containing the path to the Safety known flaws file.

    Returns:
        dict: dictionary containing the Safety known flaws properly classified.
    """
    try:
        with open(known_flaws_path, mode="r") as f:
            known_flaws = json.load(f)
    except json.decoder.JSONDecodeError or FileNotFoundError:
        known_flaws = {'known_issues': [], 'to_fix': []}

    return known_flaws


def report_for_pytest(requirements_file, known_flaws_path):
    """Method used by pytest to generate a report.

    Args:
        requirements_file (str): path to the requirements input file.
        known_flaws_path (str): path to the Safety known flaws file.

    Returns:
        str: information about packages and vulnerabilities.
    """
    prepare_input(False, requirements_file)
    result = run_report()
    known_flaws = read_known_flaws(known_flaws_path=known_flaws_path)
    result['packages'] = [flaw for flaw in result['packages'] if
                          flaw not in known_flaws['known_issues'] + known_flaws['to_fix']]
    result['vulnerabilities_found'] = len(result['packages'])
    return json.dumps(result, indent=4)
