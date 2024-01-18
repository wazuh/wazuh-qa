from ..helpers import utils
from ..helpers.constants import CLIENT_KEYS


def test_client_keys():
    assert CLIENT_KEYS.exists(), 'client.keys file not found.'


def test_client_id():
    agent_id = utils.get_client_keys()[0].get('id')
    assert agent_id, 'Agent key not found in client.keys.'


def test_register_on_server(agent_info: dict):
    expected_status = ['active', 'pending', 'never connected']
    assert agent_info.get('status') in expected_status
