import os
import re
import json
import pytest
from .helpers.wazuh_api.api import WazuhAPI

def pytest_addoption(parser):
    parser.addoption('--wazuh_version', required=False, help='Wazuh version to test files.')
    parser.addoption('--wazuh_revision', required=False, help='Wazuh revision to test.')
    parser.addoption('--system', required=False, help='OS version where wazuh was installed.')
    parser.addoption('--component', required=False, help='Component to be tested.')
    parser.addoption('--dependencies', required=False, help='Dependency to be tested.')
    parser.addoption('--live', required=True)
    parser.addoption('--one_line', required=True)

@pytest.fixture(scope='session')
def wazuh_version(request):
    return request.config.getoption('wazuh_version')


@pytest.fixture(scope='session')
def wazuh_revision(request):
    return request.config.getoption('wazuh_revision')


@pytest.fixture(scope='session')
def system(request):
    return request.config.getoption('system')


@pytest.fixture(scope='session')
def component(request):
    return request.config.getoption('component')


@pytest.fixture(scope='session')
def live(request) -> bool | None:
    live_value = request.config.getoption('live')
    return live_value.lower() == 'true' if live_value else None


@pytest.fixture(scope='session')
def one_line(request) -> bool | None:
    one_line = request.config.getoption('one_line')
    one_line = one_line.lower() == 'true' if one_line else None
    return one_line


@pytest.fixture(scope='session')
def dependencies(request) -> dict | None:
    return request.config.getoption('dependencies')


@pytest.fixture(scope='module')
def wazuh_api(dependencies: str | None) -> WazuhAPI:
    user = 'wazuh'
    password = 'wazuh'
    dependencies = json.loads(re.sub(r'(\d+\.\d+\.\d+\.\d+)', r'"\1"', re.sub(r'(\w+):', r'"\1":', dependencies)))
    host = dependencies.get('manager') if dependencies.get('manager') else 'localhost'

    print([password,user,host])
    return WazuhAPI(user, password, host)