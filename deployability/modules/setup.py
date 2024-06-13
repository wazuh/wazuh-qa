# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
import json
import os

from setuptools import setup


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


package_data_list = get_files_from_directory("jobflow")
scripts_list = ['engine=jobflow.__main__:main']

setup(
    name='jobflow',
    version=get_version(),
    description='Wazuh testing utilities to help programmers automate deployment tests',
    url='https://github.com/wazuh',
    author='Wazuh',
    author_email='hello@wazuh.com',
    license='GPLv2',
    packages=['jobflow'],
    package_dir={'jobflow': 'jobflow'},
    package_data={'jobflow': package_data_list},
    entry_points={'console_scripts': scripts_list},
    include_package_data=True,
    zip_safe=False
)
