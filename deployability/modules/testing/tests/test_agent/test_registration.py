import pytest
from ..helpers import utils
from ..helpers.constants import CLIENT_KEYS
import re
import json


@pytest.fixture
def wazuh_params(request):
    dependencies = request.config.getoption('--dependencies')

    dependencies = json.loads(re.sub(r'(\d+\.\d+\.\d+\.\d+)', r'"\1"', re.sub(r'(\w+):', r'"\1":', dependencies)))

    return {
        'dependencies': dependencies
    }

def register_agent(wazuh_params):
    result = utils.run_command("cat", ["/var/ossec/etc/ossec.conf"])
    lines = result.split('\n')
    filtered_lines = [line for line in lines if "address" in line]
    output = '\n'.join(filtered_lines)

    if 'MANAGER_IP' in output:
        manager_ip = wazuh_params['dependencies'].get('manager')
        command = f"sed -i 's/<address>MANAGER_IP<\/address>/<address>{manager_ip}<\/address>/g' /var/ossec/etc/ossec.conf"
        utils.run_command("bash", ["-c", command])

    utils.run_command('systemctl', ['restart', 'wazuh-agent'])

def test_register(wazuh_params):
    register_agent(wazuh_params)
    assert 'running' in utils.run_command('systemctl', ['status', 'wazuh-agent'])

def test_client_keys_file():
    assert CLIENT_KEYS.exists(), 'client.keys file not found.'

def test_client_id_local():
    agent_id = utils.get_client_keys()[0].get('id')
    assert agent_id, 'Agent key not found in client.keys.'

def test_local_connection_status(agent_id: str) -> None:
    expected_status = 'connected'
    assert utils.check_agent_is_connected(agent_id)
    assert utils.get_agent_connection_status(agent_id) == expected_status, 'Agent not connected to manager.'
