import pytest
import os

from time import sleep

import wazuh_testing.tools.agent_simulator as ag

from wazuh_testing.tools.thread_executor import ThreadExecutor
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing import remote as rd
from wazuh_testing import TCP, UDP

# Marks
pytestmark = pytest.mark.tier(level=0)

# Variables
current_test_path = os.path.dirname(os.path.realpath(__file__))
test_data_path = os.path.join(current_test_path, 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_invalid_protocol_communication.yaml')

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

# Set configuration
parameters = [
    {'PROTOCOL': TCP, 'PORT': 1514},
    {'PROTOCOL': UDP, 'PORT': 1514},
    {'PROTOCOL': TCP, 'PORT': 56000},
    {'PROTOCOL': UDP, 'PORT': 56000}
]

metadata = [
    {'protocol': TCP, 'port': 1514},
    {'protocol': UDP, 'port': 1514},
    {'protocol': TCP, 'port': 56000},
    {'protocol': UDP, 'port': 56000}
]

agent_info = {
    'manager_address': '127.0.0.1',
    'os': 'debian7',
    'version': '4.2.0',
    'disable_all_modules': True
}

configuration_ids = [f"{item['PROTOCOL'].upper()}_{item['PORT']}" for item in parameters]

# Configuration data
configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)


def validate_agent_manager_protocol_communication(protocol=TCP, manager_port=1514):
    """Check the communication between the agent-manager using different protocols.

    Args:
        protocol (str): It can be only TCP or UDP.
        manager_port (int): Manager remote communication port.

    Raises:
        ConnectionRefusedError: If communication could not be established with the socket.
        TimeoutError: If the event could not be found in the socket queue.
    """
    def send_event(event, protocol, manager_port):
        """Send an event to the manager"""
        print(f"Sending {protocol}")
        sender = ag.Sender(agent_info['manager_address'], protocol=protocol, manager_port=manager_port)

        try:
            sender.send_event(event)
        finally:
            sender.socket.close()

    # Create agent and sender
    agent = ag.Agent(manager_address=agent_info['manager_address'], os=agent_info['os'], version=agent_info['version'])

    # Wait until remoted has loaded the new agent key
    rd.wait_to_remoted_key_update(wazuh_log_monitor)

    # Generate a custom event
    search_pattern = f"test message from agent {agent.id}"
    agent_custom_message = f"1:/test.log:Feb 23 17:18:20 manager sshd[40657]: {search_pattern}"
    event = agent.create_event(agent_custom_message)

    send_event_thread = ThreadExecutor(send_event, {'event': event, 'protocol': protocol, 'manager_port': manager_port})

    # If protocol is TCP, then just send the message as the attempt to establish the connection will fail.
    if protocol == TCP:
        send_event_thread.start()
        send_event_thread.join()
    else:  # If protocol is UDP, then monitor the  socket queue to verify that the event has not been received.
        socket_monitor_thread = ThreadExecutor(rd.check_queue_socket_event, {'raw_events': search_pattern,
                                                                             'timeout': 20})
        socket_monitor_thread.start()

        # Wait 3 seconds until socket monitor is fully initialized
        sleep(3)

        send_event_thread.start()
        send_event_thread.join()

        # Wait until socket monitor thread finishes
        socket_monitor_thread.join()


# Fixtures
@pytest.fixture(scope='module', params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_invalid_protocol_communication(get_configuration, configure_environment, restart_remoted):
    """Check that the manager does not receive any event from an unallowed protocol."""
    manager_protocol = get_configuration['metadata']['protocol']
    manager_port = get_configuration['metadata']['port']
    # Swap protocols to send from an invalid protocol
    sender_protocol = TCP if manager_protocol == UDP else UDP

    if sender_protocol == TCP:
        # Check that the connection is not established
        with pytest.raises(ConnectionRefusedError):
            validate_agent_manager_protocol_communication(sender_protocol, manager_port)
            raise ValueError('The manager has established a TCP connection when only UDP is allowed.')
    else:
        # Check that no event is received in the socket queue
        with pytest.raises(TimeoutError):
            validate_agent_manager_protocol_communication(sender_protocol, manager_port)
            raise ValueError('The manager has received an event from a protocol not allowed.')
