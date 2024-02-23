import pytest

from ..helpers import utils
from ..helpers.constants import WAZUH_CONTROL


@pytest.fixture(scope='module', autouse=True)
def stop_wazuh():
    utils.run_command(WAZUH_CONTROL, ['stop'])
    utils.run_command('systemctl', ['stop', 'wazuh-agent'])
    yield

@pytest.fixture(scope='session', autouse=True)
def restart_wazuh_agent():
    yield
    utils.run_command('systemctl', ['restart', 'wazuh-agent'])

def test_process_not_running():
    assert not utils.is_process_alive('wazuh'), 'Wazuh process is running.'

def test_service_stopped():
    assert utils.get_service_status() == "inactive", "Service is active."

def test_ports_not_listening():
    assert not utils.is_port_in_use(1514), 'Port 1514 is listening.'
    assert not utils.is_port_in_use(1515), 'Port 1515 is listening.'
