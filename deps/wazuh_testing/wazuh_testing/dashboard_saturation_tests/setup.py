import json
from setuptools import setup, find_packages
import os


package_data_list = [
    'data/dashboard_saturation_tests.py'
]


scripts_list = [
    'dashboard-saturation-tests=data.dashboard_saturation_tests:main'
]


def get_version():
    script_path = os.path.dirname(__file__)
    rel_path = "version.json"
    abs_file_path = os.path.join(script_path, rel_path)
    f = open(abs_file_path)
    data = json.load(f)
    version = data['version']
    return version


setup(
    name='wazuh_testing',
    version=get_version(),
    description='Wazuh testing utilities to help programmers automate tests',
    url='https://github.com/wazuh',
    author='Wazuh',
    author_email='hello@wazuh.com',
    license='GPLv2',
    packages=find_packages(),
    package_data={'data': package_data_list},
    entry_points={'console_scripts': scripts_list},
    include_package_data=True,
    zip_safe=False
)