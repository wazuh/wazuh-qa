# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2


from setuptools import setup, find_packages


setup(name='wazuh_testing',
      version='3.11.0',
      description='Wazuh testing utilites to help programmers automate tests',
      url='https://github.com/wazuh',
      author='Wazuh',
      author_email='hello@wazuh.com',
      license='GPLv2',
      packages=find_packages(),
      package_data={'wazuh_testing': ['data/syscheck_event.json',
                                      'data/syscheck_event_windows.json',
                                      'data/mitre_event.json',
                                      'data/event_analysis_schema.json',
                                      'data/state_integrity_analysis_schema.json']
                    },
      include_package_data=True,
      zip_safe=False
      )
