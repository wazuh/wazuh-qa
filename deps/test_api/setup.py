# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from setuptools import setup, find_packages

NAME = "test_api"
VERSION = "1.0.0"

# To install the library, run the following
#
# python setup.py install
#
# prerequisite: setuptools
# http://pypi.python.org/pypi/setuptools

REQUIRES = ["connexion[swagger-ui]==2.2.0",
            "Flask==1.0.2",
            "python_dateutil==2.8.0",
            "PyYAML==3.13",
            "setuptools>=21.0.0",
            ]

setup(
    name=NAME,
    version=VERSION,
    description="Test API. Only for testing purposes.",
    author_email="hello@wazuh.com",
    author="Wazuh",
    url="https://github.com/wazuh-qa",
    keywords=["Wazuh Test API"],
    install_requires=REQUIRES,
    packages=find_packages(exclude=["*.test", "*.test.*", "test.*", "test"]),
    package_data={'': ['spec/spec.yaml']},
    include_package_data=True,
    zip_safe=False,
    license='GPLv2',
    long_description="""This API give support for testing complex environments by installing it in all hosts."""
)