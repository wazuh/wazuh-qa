import os
import pytest
from time import sleep

from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.services import control_service
from wazuh_testing.agent import (callback_connected_to_server, callback_unable_to_connect,
                callback_invalid_server_address, callback_could_not_resolve_hostname)

TIMEOUT = 30

# Marks
pytestmark = pytest.mark.tier(level=0)

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
daemons_handler_configuration = {'daemons': ['wazuh-agentd'], 'ignore_errors': True}
local_internal_options = {'agent.debug': '2'}

parameters = [
    {'SERVER_IP': 'MANAGER_IP'},                               # Invalid server address
    {'SERVER_IP': '172.28.128.hello'},                         # Could not resolve hostname
    {'SERVER_IP': '172.28.128.12'},                            # Valid IP, unable to connect (IPv4)
    {'SERVER_IP': '172.28.128.20'},                            # Valid IP, connected (IPv4)
    {'SERVER_IP': '::ffff:ac1c:800c'},                         # Valid IP, unable to connect (IPv6 compressed)
    {'SERVER_IP': '::ffff:ac1c:8014'},                         # Valid IP, connected (IPv6 compressed)
    {'SERVER_IP': '0000:0000:0000:0000:0000:ffff:ac1c:800c'},  # Valid IP, unable to connect (IPv6 expanded)
    {'SERVER_IP': '0000:0000:0000:0000:0000:ffff:ac1c:8014'},  # Valid IP, connected (IPv6 expanded)
    {'SERVER_IP': 'unable'},                                   # Resolve hostname, valid IP, unable to connect (IPv4)
    {'SERVER_IP': 'connected'},                                # Resolve hostname, Valid IP, connected (IPv4)
    {'SERVER_IP': 'unable6compressed'},                        # Resolve hostname, valid IP, unable to connect (IPv6 compressed)
    {'SERVER_IP': 'connected6compressed'},                     # Resolve hostname, Valid IP, connected (IPv6 compressed)
    {'SERVER_IP': 'unable6'},                                  # Resolve hostname, valid IP, unable to connect (IPv6 expanded)
    {'SERVER_IP': 'connected6'}                                # Resolve hostname, Valid IP, connected (IPv6 expanded)
]

metadata = [
    {'server_ip': 'MANAGER_IP', 'message_type': 0},                               # Invalid server address
    {'server_ip': '172.28.128.hello', 'message_type': 1},                         # Could not resolve hostname
    {'server_ip': '172.28.128.12', 'message_type': 2},                            # Valid IP, unable to connect (IPv4)
    {'server_ip': '172.28.128.20', 'message_type': 3},                            # Valid IP, connected (IPv4)
    {'server_ip': '::ffff:ac1c:800c', 'message_type': 2},                         # Valid IP, unable to connect (IPv6 compressed)
    {'server_ip': '::ffff:ac1c:8014', 'message_type': 3},                         # Valid IP, connected (IPv6 compressed)
    {'server_ip': '0000:0000:0000:0000:0000:ffff:ac1c:800c', 'message_type': 2},  # Valid IP, unable to connect (IPv6 expanded)
    {'server_ip': '0000:0000:0000:0000:0000:ffff:ac1c:8014', 'message_type': 3},  # Valid IP, connected (IPv6 expanded)
    {'server_ip': 'unable', 'message_type': 2},                                   # Resolve hostname, valid IP, unable to connect (IPv4)
    {'server_ip': 'connected', 'message_type': 3},                                # Resolve hostname, Valid IP, connected (IPv4)
    {'server_ip': 'unable6compressed', 'message_type': 2},                        # Resolve hostname, valid IP, unable to connect (IPv6 compressed)
    {'server_ip': 'connected6compressed', 'message_type': 3},                     # Resolve hostname, Valid IP, connected (IPv6 compressed)
    {'server_ip': 'unable6', 'message_type': 2},                                  # Resolve hostname, valid IP, unable to connect (IPv6 expanded)
    {'server_ip': 'connected6', 'message_type': 3}                                # Resolve hostname, Valid IP, connected (IPv6 expanded)
]

# Configuration data
configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)
configuration_ids = [f"{x['SERVER_IP']}" for x in parameters]
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

# Functions
def switch(n):
    callback_message = (None, None)
    if n == 0:
        callback_message = (
            callback_invalid_server_address,
            f"The expected 'Invalid server address found' message has not been produced"
        )
    elif n == 1:
        callback_message = (
            callback_could_not_resolve_hostname,
            f"The expected 'Could not resolve hostname' message has not been produced"
        )
    elif n == 2:
        callback_message = (
            callback_unable_to_connect,
            f"The expected 'Unable to connect to' message has not been produced"
        )
    elif n == 3:
        callback_message = (
            callback_connected_to_server,
            f"The expected 'Connected to the server' message has not been produced"
        )

    return callback_message


# Fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param

# Tests
def test_agentd_server_configuration(get_configuration, configure_environment, configure_local_internal_options_module,
                daemons_handler, file_monitoring):


    message_type = get_configuration['metadata']['message_type']
    callback_message = switch(message_type)
    log_monitor.start(timeout=TIMEOUT, callback=callback_message[0], error_message=callback_message[1])
