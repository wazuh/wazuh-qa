import os
import subprocess
import pytest
from time import sleep

from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.services import control_service
import wazuh_testing.agent as agent

TIMEOUT = 30

# Marks
pytestmark = pytest.mark.tier(level=0)

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
daemons_handler_configuration = {'daemons': ['wazuh-agentd'], 'ignore_errors': True}
local_internal_options = {'agent.debug': '2'}

parameters = [
    {'SERVER_ADDRESS': 'MANAGER_IP'},                               # Invalid server address
    {'SERVER_ADDRESS': '172.28.128.hello'},                         # Could not resolve hostname
    {'SERVER_ADDRESS': '172.28.128.12'},                            # Valid IP, unable to connect (IPv4)
    {'SERVER_ADDRESS': '::ffff:ac1c:800c'},                         # Valid IP, unable to connect (IPv6 compressed)
    {'SERVER_ADDRESS': '0000:0000:0000:0000:0000:ffff:ac1c:800c'},  # Valid IP, unable to connect (IPv6 expanded)
    {'SERVER_ADDRESS': 'unable'},                                   # Resolve hostname, valid IP, unable to connect (IPv4)
    {'SERVER_ADDRESS': 'unable6compressed'},                        # Resolve hostname, valid IP, unable to connect (IPv6 compressed)
    {'SERVER_ADDRESS': 'unable6'}                                   # Resolve hostname, valid IP, unable to connect (IPv6 expanded)
]

metadata = [
    {'server_address': 'MANAGER_IP',                              'invalid_address': True,  'resolve_hostname': False},
    {'server_address': '172.28.128.hello',                        'invalid_address': False, 'resolve_hostname': False},
    {'server_address': '172.28.128.12',                           'invalid_address': False, 'resolve_hostname': True},
    {'server_address': '::ffff:ac1c:800c',                        'invalid_address': False, 'resolve_hostname': True},
    {'server_address': '0000:0000:0000:0000:0000:ffff:ac1c:800c', 'invalid_address': False, 'resolve_hostname': True},
    {'server_address': 'unable', 'invalid_address': False, 'resolve_hostname': True, 'real_ip': '172.28.128.12'},
    {'server_address': 'unable6compressed', 'invalid_address': False, 'resolve_hostname': True, 'real_ip': '::ffff:ac1c:800c'},
    {'server_address': 'unable6', 'invalid_address': False, 'resolve_hostname': True, 'real_ip': '0000:0000:0000:0000:0000:ffff:ac1c:800c'}
]

# Configuration data
configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)
configuration_ids = [f"{x['SERVER_IP']}" for x in parameters]

# Functions


# Fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param

@pytest.fixture(scope="module")
def edit_hosts(get_configuration):
    if 'real_ip' in get_configuration['metadata']:
        with open('/etc/hosts', 'r+') as file:
            original_content = file.read()

            new_content = get_configuration['metadata']['real_ip'] + ' ' + get_configuration['metadata']['server_address']
            file.write(new_content)

    yield

    if 'real_ip' in get_configuration['metadata']:
        with open('/etc/hosts', 'w') as file:
            file.write(original_content)

# Tests
def test_agentd_server_configuration(get_configuration, configure_environment, configure_local_internal_options_module,
                edit_hosts, daemons_handler, file_monitoring):


    cfg = get_configuration['metadata']
    if cfg['invalid_address']:
        callback = agent.callback_invalid_server_address(cfg['server_address'])
        log_monitor.start(timeout=TIMEOUT, callback=callback,
                                error_message=f"The expected 'Invalid server address found' message has not been produced")
    else:
        if not cfg['resolve_hostname']:
            callback = agent.callback_could_not_resolve_hostname(cfg['server_address'])
            log_monitor.start(timeout=TIMEOUT, callback=callback,
                                    error_message=f"The expected 'Could not resolve hostname' message has not been produced")
        else:
            if 'real_ip' in cfg:
                ip = cfg['real_ip']
            else:
                ip = cfg['server_address']
            
            callback = agent.callback_unable_to_connect(ip)
            log_monitor.start(timeout=TIMEOUT, callback=callback,
                                    error_message=f"The expected 'Unable to connect to' message has not been produced")
