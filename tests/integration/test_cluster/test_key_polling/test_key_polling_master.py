import os
import re

import pytest
from wazuh_testing.cluster import FERNET_KEY, cluster_msg_build
from wazuh_testing.tools import WAZUH_PATH, CLUSTER_LOGS_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import ManInTheMiddle

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0)]

# Configurations

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'cluster_conf.yaml')
params = [{'FERNET_KEY': FERNET_KEY}]
metadata = [{'fernet_key': FERNET_KEY}]
configurations = load_wazuh_configurations(configurations_path, __name__, params=params, metadata=metadata)

# Variables

log_monitor_paths = [CLUSTER_LOGS_PATH]
modulesd_socket_path = os.path.join(WAZUH_PATH, 'queue', 'sockets', 'krequest')
cluster_socket_address = ('localhost', 1516)

receiver_sockets_params = [(cluster_socket_address, 'AF_INET', 'TCP')]  # SocketController items

mitm_modules = ManInTheMiddle(address=modulesd_socket_path, family='AF_UNIX', connection_protocol='UDP')
# monitored_sockets_params is a List of daemons to start with optional ManInTheMiddle to monitor
# List items -> (wazuh_daemon: str,(
#                mitm: ManInTheMiddle
#                daemon_first: bool))
# Example1 -> ('wazuh-clusterd', None)              Only start wazuh-clusterd with no MITM
# Example2 -> ('wazuh-clusterd', (my_mitm, True))   Start MITM and then wazuh-clusterd
monitored_sockets_params = [('wazuh-clusterd', None, None), ('wazuh-modulesd', mitm_modules, True)]

receiver_sockets, monitored_sockets, log_monitors = None, None, None  # Set in the fixtures


# Functions


def callback_krequest(item):
    # Regex to match krequest socket received message being id:AGENT_VALID_ID or ip:AGENT_VALID_IP
    reg = r'^(id:[\d]{3}|ip:((\d|[1-9]\d|1\d{2}|2[0-4]\d|25[0-5])\.){3}(\d|[1-9]\d|1\d{2}|2[0-4]\d|25[0-5]))'
    match = re.match(reg, item.decode())
    if match:
        return item.decode()


# Fixtures


@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Tests

@pytest.mark.skip(reason='Development in progress: https://github.com/wazuh/wazuh/issues/4387')
@pytest.mark.parametrize('cmd, counter, payload, expected', [
    (b'run_keypoll', 1, b'{"message": "id:001"}', "id:001"),
    (b'run_keypoll', 2, b'{"message": "ip:124.0.0.1"}', "ip:124.0.0.1")
])
def test_key_polling_master(cmd, counter, payload, expected, configure_environment, configure_sockets_environment,
                            detect_initial_master_serving, connect_to_sockets_module, send_initial_worker_hello):
    """
    Test master behaviour with agent key-polling.

    This test uses a fictional worker node to test wazuh master behaviour against agent-key-polling messages. After
    connecting the fictional worker to the master and sending the initial hello, the test sends another worker simulated
    message representing a key-polling request. Then, we ensure that the master completed his duty by checking the
    received message in the other end, in this case, krequest socket handled by modulesd.

    Parameters
    ----------
    cmd : bytes
        Cluster message command
    counter : int
        Cluster message counter
    payload : bytes
        Cluster message payload data
    expected : str
        Expected message in krequest socket
    """
    # Build message and send it to the master
    message = cluster_msg_build(cmd=cmd, counter=counter, payload=payload, encrypt=True)
    receiver_sockets[0].send(message)

    # Ensure krequest socket (modulesd socket for key-polling) receives the appropriate data
    result = monitored_sockets[0].start(timeout=5, callback=callback_krequest).result()

    assert result == expected
