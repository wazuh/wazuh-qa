import os
import pytest
import xml.etree.ElementTree as ET

from typing import List

from wazuh_testing.tools.system import HostManager
from wazuh_testing.tools import WAZUH_PATH

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
    """
    Update OSSEC configuration on the Wazuh manager using the API.

    Parameters
    ----------
    host_manager : HostManager
        The host manager object responsible for managing hosts.
    ossec_configuration_file : str
        The OSSEC configuration file content.
    port : int, optional
        The port number for the Wazuh manager API. Default is 55000.

    Returns
    -------
    AnsibleResult
        The result of the Ansible URI module execution.
    """
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


def add_blocks_to_xml(original_xml_tree: ET.ElementTree, xmls_files: List[str], path_to_files: str):
    """
    Add XML blocks to the original XML tree.

    Parameters
    ----------
    original_xml_tree : ElementTree
        The original XML tree.
    xmls_files : List[str]
        List of XML file names to be added.
    path_to_files : str
        Path to the directory containing XML files.

    Returns
    -------
    str
        The resulting XML after adding the specified blocks.
    """
    blocks_to_add = [ET.tostring(original_xml_tree.getroot(), encoding='utf-8').decode('utf-8')]
    for block_file_path in xmls_files:
        block_string = ET.tostring(ET.parse(os.path.join(path_to_files, block_file_path)).getroot(), encoding='utf-8').decode('utf-8')
        blocks_to_add.append(block_string)

    new_xml = '\n\n'.join(blocks_to_add)
    return new_xml

@pytest.fixture(scope='function')
def setup_environment():
    """
    Fixture for setting up the environment for testing.

    This fixture saves the original OSSEC config, cleans the API config, and yields control to the test function.
    After the test function execution, it cleans the API config again and reverts the OSSEC config to the original one.
    """
    # Saves the original ossec config
    original_ossec_config = host_manager.get_file_content('wazuh-manager', ossec_conf_path)

    # Cleans the api config
    host_manager.apply_api_config({}, ['wazuh-manager'])

    yield

    # Cleans the api config
    host_manager.apply_api_config({}, ['wazuh-manager'])
    # Reverts the config to the original one
    update_ossec_config_with_api(host_manager, original_ossec_config)


@pytest.mark.parametrize('ossec_config_blocks, api_configuration_file, new_ossec_config_blocks, expected_to_update',
                         [
                             (['block.xml'], 'not_allowed_limit_eps.yml', ['block_changed.xml'], False),
                             (['block.xml'], 'allowed_limit_eps.yml', ['block_changed.xml'], True),
                             (['block.xml', 'block.xml'], 'not_allowed_limit_eps.yml', ['block_changed.xml', 'block_unchanged.xml'], False),
                             (['block.xml', 'block.xml'], 'allowed_limit_eps.yml', ['block_changed.xml', 'block_unchanged.xml'], True),
                             (['block.xml', 'block.xml'], 'not_allowed_limit_eps.yml', ['block_unchanged.xml', 'block_changed.xml'], False),
                             (['block.xml', 'block.xml'], 'allowed_limit_eps.yml', ['block_unchanged.xml', 'block_changed.xml'], True)
                         ])
def test_limit_eps(setup_environment, ossec_config_blocks, api_configuration_file, new_ossec_config_blocks, expected_to_update):
    """
    Test the limit_eps functionality.

    Parameters
    ----------
    setup_environment : fixture
        Fixture for setting up the environment for testing.
    ossec_config_blocks : List[str]
        List of XML block files to be added to the original OSSEC config.
    api_configuration_file : str
        API configuration file.
    new_ossec_config_blocks : List[str]
        List of new XML block files to be added after applying API configuration.
    expected_to_update : bool
        Whether the configuration is expected to be updated without errors.

    """
    # Get original ossec config file content
    original_ossec_config = host_manager.get_file_content('wazuh-manager', ossec_conf_path)
    original_ossec_file_tree = ET.ElementTree(ET.fromstring(original_ossec_config))

    # Add multiples blocks to the ossec config
    new_ossec_config = add_blocks_to_xml(original_ossec_file_tree, ossec_config_blocks, ossec_configurations_test_path)
    response = update_ossec_config_with_api(host_manager, new_ossec_config)

    # Assert the configuration updated as expected
    assert response['status'] == 200 and response['json']['error'] == 0, f'Failed to update configuration: {response}'

    # Apply api configuration
    host_manager.apply_api_config(os.path.join(api_configurations_test_path, api_configuration_file), ['wazuh-manager'])

    # Creates new ossec config with the updated values
    new_ossec_config = add_blocks_to_xml(original_ossec_file_tree, new_ossec_config_blocks, xml_data_blocks_path)
    response = update_ossec_config_with_api(host_manager, new_ossec_config)

    assert response['status'] == 200, f'Failed to update configuration: {response}'
    # Check if there was an error updating the new configuration file
    if expected_to_update:
        assert response['json']['error'] == 0, f'Expected no error updating the configuration'
    else:
        assert response['json']['error'] == 1, f'Expected error updating the configuration'
