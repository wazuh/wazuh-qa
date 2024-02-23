import pytest

from ..helpers import utils
from ..helpers.constants import WAZUH_CONTROL


@pytest.fixture(scope='module', autouse=True)
def restart_wazuh():
    utils.run_command(WAZUH_CONTROL, ['restart'])

def test_service_started():
    assert utils.get_service_status() == "active", "Service is not active after restart."

def test_local_connection_status(agent_id: str) -> None:
    expected_status = 'connected'
    assert utils.check_agent_is_connected(agent_id)
    assert utils.get_agent_connection_status(agent_id) == expected_status, 'Agent not connected to manager.'

def test_server_connection_status(agent_info: dict) -> None:
    expected_status = 'active'
    assert agent_info.get('status') == expected_status, 'Agent not connected to manager.'
