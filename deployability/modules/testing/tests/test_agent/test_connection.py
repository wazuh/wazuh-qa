from ..helpers import utils
from ..helpers.constants import CLIENT_KEYS, CONNECTION_AGENT, WAZUH_LOG



def test_agent_connects_to_manager(wazuh_api_client):
    keys = utils.get_client_keys()
    agent_info = wazuh_api_client.get_agent(keys[0].get('id'))
    print(agent_info)

def test_agent_connection_status():
    expected_status = "connected"

    assert utils.check_agent_is_connected("001")
    assert utils.get_agent_connection_status("001") == expected_status
