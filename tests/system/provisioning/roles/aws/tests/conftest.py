import pytest

def pytest_addoption(parser):
    parser.addoption(
        "--user", action="store", default="wazuh", help="SSH user configured in 'ssh_username' variable"
    )
    parser.addoption(
        "--ssh_key", action="store", default="wazuh", help="SSH Key configured in 'custom_ssh_key' variable"
    )

@pytest.fixture
def user(request):
    return request.config.getoption("--user")

@pytest.fixture
def ssh_key(request):
    return request.config.getoption("--ssh_key")