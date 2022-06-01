import os
import pytest

from wazuh_testing.tools import file


credentials_file = os.path.join('/tmp', 'passwords.wazuh')


@pytest.fixture(scope="function")
def get_opensearch_credentials():
    user = ''
    password = ''

    for line in file.get_file_lines(credentials_file):
        if 'username: admin' in line:
            user = 'admin'
        if user != '' and 'password: ' in line:
            password = line.split()[1]

    yield user, password
