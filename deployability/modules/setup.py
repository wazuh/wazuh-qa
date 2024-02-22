
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import json
from setuptools import setup, find_packages
import os
from pathlib import Path

def get_files_from_directory(directory):
    paths = []
    base_path = Path(__file__)
    for (path, directories, filenames) in os.walk(directory):
        for filename in filenames:
            if filename.endswith(('.yaml', '.json', '.md', '.py')):
                paths.append(os.path.join(base_path, path, filename))
    return paths

def get_version():
    abs_path = Path(__file__).parent.parent / "version.json"

    if not os.path.exists(abs_path):
        raise FileNotFoundError(f'File "{abs_path}" not found.')

    with open(abs_path, 'r') as abs_file:
        data = json.load(abs_file)
        version = data['version']
    return version or None

package_data_list = get_files_from_directory("workflow_engine")
scripts_list = ['engine=workflow_engine.__main__:main']

setup(
    name='workflow_engine',
    version=get_version(),
    description='Wazuh testing utilities to help programmers automate deployment tests',
    url='https://github.com/wazuh',
    author='Wazuh',
    author_email='hello@wazuh.com',
    license='GPLv2',
    packages=['workflow_engine'],
    package_dir={'workflow_engine': 'workflow_engine'},
    package_data={'workflow_engine': package_data_list},
    entry_points={'console_scripts': scripts_list},
    include_package_data=True,
    zip_safe=False
)