# Copyright (C) 2015-2022, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import pytest
from tempfile import gettempdir

from wazuh_testing.tools.file import remove_file, get_file_lines


alerts_json = os.path.join(gettempdir(), 'alerts.json')
credentials_file = os.path.join(gettempdir(), 'passwords.wazuh')


@pytest.fixture(scope='function')
def clean_environment():
    """Delete alerts and credentials files from the temporary folder."""
    yield

    remove_file(alerts_json)
    remove_file(credentials_file)


@pytest.fixture(scope='function')
def get_dashboard_credentials():
    """Get wazuh-dashboard username and password.

       Returns:
            dict: wazuh-dashboard credentials.
    """
    password = ''
    user = ''

    for line in get_file_lines(credentials_file):
        if 'username: admin' in line:
            user = 'admin'

        if 'password: ' in line and user == 'admin':
            password_line = line
            password = password_line.split()[1]

        if user != '' and password != '':
            break

    dashboard_credentials = {'user': user, 'password': password}

    yield dashboard_credentials
