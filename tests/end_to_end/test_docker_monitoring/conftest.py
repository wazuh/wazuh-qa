# Copyright (C) 2015-2022, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import pytest
from tempfile import gettempdir

from wazuh_testing.tools import file


credentials_file = os.path.join(gettempdir(), 'passwords.wazuh')


@pytest.fixture(scope="function")
def get_opensearch_credentials():
    user = ''
    password = ''

    for line in file.get_file_lines(credentials_file):
        if 'username: admin' in line:
            user = 'admin'
        if user != '' and password == '' and 'password: ' in line:
            password = line.split()[1]

    yield user, password
