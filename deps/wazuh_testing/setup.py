# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2


from setuptools import setup, find_packages


setup(name='wazuh_testing',
      version='4.0.0',
      description='Wazuh testing utilites to help programmers automate tests',
      url='https://github.com/wazuh',
      author='Wazuh',
      author_email='hello@wazuh.com',
      license='GPLv2',
      packages=find_packages(),
      package_data={'wazuh_testing': ['data/syscheck_event.json',
                                      'data/syscheck_event_windows.json',
                                      'data/mitre_event.json',
                                      'data/analysis_alert.json',
                                      'data/analysis_alert_windows.json',
                                      'data/state_integrity_analysis_schema.json',
                                      'data/gcp_event.json',
                                      'data/keepalives.txt'
                                      ]
                    },
      include_package_data=True,
      install_requires=[
            'lockfile==0.12.2',
            'testinfra==5.0.0',
            'filetype==1.0.7',
            'requests==2.23.0',
            'pyOpenSSL==19.1.0',
            'pycryptodome==3.9.8',
            'configobj'
      ],
      zip_safe=False
      )
