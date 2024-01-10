import os

import pytest


def pytest_addoption(parser):
    parser.addoption('--wazuh_version', required=False, help='Wazuh version to test files.')
    parser.addoption('--wazuh_revision', required=False, help='Wazuh revision to test.')
    parser.addoption('--system', required=False, help='OS version where wazuh was installed.')
    parser.addoption('--component', required=False, help='Component to be tested.')


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
