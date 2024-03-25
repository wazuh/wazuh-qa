import pytest


def pytest_addoption(parser):
    parser.addoption('--wazuh_version', required=False, help='Wazuh version to test files.')
    parser.addoption('--wazuh_revision', required=False, help='Wazuh revision to test.')
    parser.addoption('--system', required=False, help='OS version where wazuh was installed.')
    parser.addoption('--component', required=False, help='Component to be tested.')
    parser.addoption('--dependencies', required=False, help='Dependency to be tested.')
    parser.addoption('--targets', required=False, help='Targets to be tested.')


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
def dependencies(request) -> dict | None:

    return request.config.getoption('dependencies')


@pytest.fixture(scope='session')
def targets(request) -> dict | None:

    return request.config.getoption('targets')