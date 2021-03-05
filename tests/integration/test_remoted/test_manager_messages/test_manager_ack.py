import pytest
import os
import wazuh_testing.tools.agent_simulator as ag

from time import sleep
from wazuh_testing import remote as rd
from wazuh_testing.tools import LOG_FILE_PATH, is_tcp_udp
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor


# Marks
pytestmark = pytest.mark.tier(level=1)

# Variables
current_test_path = os.path.dirname(os.path.realpath(__file__))
test_data_path = os.path.join(current_test_path, 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_manager_ack.yaml')

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

# Set configuration
parameters = [
    {'PROTOCOL': 'tcp'},
    {'PROTOCOL': 'udp'},
    {'PROTOCOL': 'tcp,udp'},
    {'PROTOCOL': 'udp,tcp'},
]

metadata = [
    {'protocol': 'tcp'},
    {'protocol': 'udp'},
    {'protocol': 'tcp,udp'},
    {'protocol': 'udp,tcp'},
]

agent_info = {
    'manager_address': '127.0.0.1',
    'os': 'debian7',
    'version': '4.2.0',
    'disable_all_modules': True
}

configuration_ids = [item['PROTOCOL'].upper() for item in parameters]

# Configuration data
configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)


def check_manager_ack(protocol):
    """Allow to check if the manager sends the ACK message after receiving the start-up message from agent.

    Args:
        protocol (str): It can be UDP or TCP.

    Raises:
        TimeoutError: If agent does not receive the manager ACK message in the expected time.
    """

    # Create agent and sender object with default parameters
    agent = ag.Agent(**agent_info)

    # Sleep to avoid ConnectionRefusedError
    sleep(1)

    sender = ag.Sender(agent_info['manager_address'], protocol=protocol)

    # Activate receives_messages modules in simulated agent.
    agent.set_module_status('receive_messages', 'enabled')

    # Run injector with only receive messages module enabled
    injector = ag.Injector(sender, agent)
    try:
        injector.run()

        # Wait until remoted has loaded the new agent key
        rd.wait_to_remoted_key_update(wazuh_log_monitor)

        # Send the start-up message
        sender.send_event(agent.startup_msg)

        # Check ACK manager message
        rd.check_agent_received_message(agent.rcv_msg_queue, '#!-agent ack')
    finally:
        injector.stop_receive()


@pytest.fixture(scope='module', params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_manager_ack(get_configuration, configure_environment, restart_remoted):
    """Check if the manager sends the ACK message after receiving the start-up message from the agent."""
    protocol = get_configuration['metadata']['protocol']

    if is_tcp_udp(protocol):
        check_manager_ack(rd.TCP)
        check_manager_ack(rd.UDP)
    else:
        check_manager_ack(protocol)
