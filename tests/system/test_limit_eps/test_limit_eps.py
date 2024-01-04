import os
import pytest
import xml.etree.ElementTree as ET

from wazuh_testing.tools.system import HostManager
from wazuh_testing.tools.file import read_file, read_yaml
from wazuh_testing.tools import WAZUH_PATH
from wazuh_testing.api import make_api_call

pytestmark = [pytest.mark.basic_environment_env]

# Hosts
testinfra_hosts = ['wazuh-manager', 'wazuh-agent1']

inventory_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                              'provisioning', 'basic_environment', 'inventory.yml')
host_manager = HostManager(inventory_path)
local_path = os.path.dirname(os.path.abspath(__file__))


api_configurations_test_path = os.path.join(local_path, 'api_configurations')
ossec_configurations_test_path = os.path.join(local_path, 'ossec_config')
xml_data_blocks_path = os.path.join(local_path, 'data')

ossec_conf_path = os.path.join(WAZUH_PATH, 'etc', 'ossec.conf')


def update_ossec_config_with_api(host_manager, ossec_configuration_file, port=55000):
    # Get API token
    token = host_manager.get_api_token(host='wazuh-manager')

    # Define endpoint, headers, body, method
    endpoint = '/manager/configuration'
    headers = {'Content-Type': 'application/octet-stream', 'Authorization': f'Bearer {token}'}
    body = 'body="{}"'.format(ossec_configuration_file)
    method = 'PUT'

    # Form the Ansible URI module command
    ansible_command = f'url="https://localhost:{port}{endpoint}" ' \
                      f'method={method} headers="{headers}" {body} validate_certs=no'

    # Execute the Ansible URI module
    return host_manager.get_host('wazuh-manager').ansible('uri', ansible_command, check=False)


def clean_api_config(host_manager):
    host_manager.apply_api_config({}, ['wazuh-manager'])


@pytest.mark.parametrize('ossec_config_blocks, api_configuration_file, new_ossec_config_blocks, expected_to_update',
                         [
                            (['block.xml'], 'not_allowed_limit_eps.yml', ['block_changed.xml'], False),
                            (['block.xml'], 'allowed_limit_eps.yml', ['block_changed.xml'], True),
                            (['block.xml', 'block.xml'], 'not_allowed_limit_eps.yml', ['block_changed.xml', 'block_unchanged.xml'], False),
                            (['block.xml', 'block.xml'], 'allowed_limit_eps.yml', ['block_changed.xml', 'block_unchanged.xml'], True),
                            (['block.xml', 'block.xml'], 'not_allowed_limit_eps.yml', ['block_unchanged.xml', 'block_changed.xml'], False),
                            (['block.xml', 'block.xml'], 'allowed_limit_eps.yml', ['block_unchanged.xml', 'block_changed.xml'], True)
                         ])
def test_limit_eps(ossec_config_blocks, api_configuration_file, new_ossec_config_blocks, expected_to_update):
    # Clean API Configuration
    clean_api_config(host_manager)

    # Get original ossec config file content
    original_ossec_config = host_manager.get_file_content('wazuh-manager', ossec_conf_path)
    original_ossec_file_tree = ET.ElementTree(ET.fromstring(original_ossec_config))

    # Add multiples blocks to the ossec config
    blocks_to_add = [ET.tostring(original_ossec_file_tree.getroot(), encoding='utf-8').decode('utf-8')]
    for block_file_path in ossec_config_blocks:
        block_string = ET.tostring(ET.parse(os.path.join(ossec_configurations_test_path, block_file_path)).getroot(), encoding='utf-8').decode('utf-8')
        blocks_to_add.append(block_string)

    new_ossec_config = '\n\n'.join(blocks_to_add)
    response = update_ossec_config_with_api(host_manager, new_ossec_config)

    # Assert the configuration updated as expected
    assert response['status'] == 200, f'Failed to update configuration: {response}'

    # Apply api configuration
    host_manager.apply_api_config(os.path.join(api_configurations_test_path, api_configuration_file), ['wazuh-manager'])

    # Creates new ossec config with the updated values
    blocks_to_add = [ET.tostring(original_ossec_file_tree.getroot(), encoding='utf-8').decode('utf-8')]
    for block_file_path in new_ossec_config_blocks:
        block_string = ET.tostring(ET.parse(os.path.join(xml_data_blocks_path, block_file_path)).getroot(), encoding='utf-8').decode('utf-8')
        blocks_to_add.append(block_string)
    new_ossec_config = '\n\n'.join(blocks_to_add)

    response = update_ossec_config_with_api(host_manager, new_ossec_config)
    print(response)
    assert response['status'] == 200, f'Failed to update configuration: {response}'
    # Check if there was an error updating the new configuration file
    if expected_to_update:
        assert response['json']['error'] == 0, f'Expected no error'
    else:
        assert response['json']['error'] == 1, f'Expected error'

    # Clean environment
    clean_api_config(host_manager)
    update_ossec_config_with_api(host_manager, original_ossec_config)

