import sys
import pytest

from .helpers.wazuh_api.api import WazuhAPI


def pytest_addoption(parser):
    parser.addoption('--wazuh_version', help='Wazuh version to test files.')
    parser.addoption('--wazuh_revision', help='Wazuh revision to test.')
    parser.addoption('--component', help='Component to be tested.')
    parser.addoption('--dependency_ip', required=False, help='IP of the dependency component.')


@pytest.fixture(scope='session')
def wazuh_version(request) -> str | None:
    return request.config.getoption('wazuh_version')


@pytest.fixture(scope='session')
def wazuh_revision(request) -> str | None:
    return request.config.getoption('wazuh_revision')


@pytest.fixture(scope='session')
def system() -> str | None:
    return sys.platform()

@pytest.fixture(scope='session')
def component(request) -> str | None:
    return request.config.getoption('component')


@pytest.fixture(scope='session')
def dependency_ip(request) -> str | None:
    return request.config.getoption('dependency_ip')


@pytest.fixture(scope='module')
def wazuh_api(dependency_ip: str | None) -> WazuhAPI:
    user = 'wazuh'
    password = 'wazuh'
    host = dependency_ip if dependency_ip else 'localhost'
    print(host)
    return WazuhAPI(user, password, host)
