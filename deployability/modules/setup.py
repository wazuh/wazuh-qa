
# Copyright (C) 2015-2024, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import json
from setuptools import setup, find_packages
import os

def get_files_from_directory(directory):
    paths = []
    for (path, directories, filenames) in os.walk(directory):
        for filename in filenames:
            paths.append(os.path.join('..', path, filename))
    return paths

def get_version():
    script_path = os.path.dirname(__file__)
    rel_path = "../version.json"
    abs_file_path = os.path.join(script_path, rel_path)
    f = open(abs_file_path)
    data = json.load(f)
    version = data['version']
    return version

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