from ..helpers import utils
from ..helpers.constants import WAZUH_LOG, CLIENT_KEYS, KEY_REQ_AGENT, KEY_REQ_SERVER


def test_register_logs_were_generated(component):
    expected_log = KEY_REQ_AGENT if component == "agent" else KEY_REQ_SERVER

    assert utils.file_monitor(WAZUH_LOG, expected_log), "Register logs not found."


def test_client_keys_file_exists():
    assert CLIENT_KEYS.exists(), 'client.keys file not found.'


def test_agent_key_is_in_client_keys():
    assert '001' in CLIENT_KEYS.read_text(), 'Agent key not found in client.keys.'
