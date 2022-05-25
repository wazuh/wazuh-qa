import os
import pytest
from wazuh_testing.tools.file import remove_file, get_file_lines

alerts_json = os.path.join('/tmp', 'alerts.json')
credentials_file = os.path.join('/tmp', 'passwords.wazuh')


@pytest.fixture(scope='function')
def clean_environment():

    yield

    remove_file(alerts_json)
    remove_file(credentials_file)


@pytest.fixture(scope='function')
def get_dashboard_credentials():

    password = ''
    user = ''

    for line in get_file_lines(credentials_file):
        if 'username: admin' in line:
            user = 'admin'

        if 'password: ' in line and user == 'admin':
            password_line = line
            password = password_line.split()[1]

    dashboard_credentials = [user, password]

    yield dashboard_credentials
