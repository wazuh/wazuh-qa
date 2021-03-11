import pytest
import os

import wazuh_testing.tools.agent_simulator as ag

from time import sleep
from wazuh_testing.tools.thread_executor import ThreadExecutor
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing import remote as rd
from wazuh_testing import TCP, UDP, TCP_UDP


# Marks
pytestmark = pytest.mark.tier(level=2)

# Variables
current_test_path = os.path.dirname(os.path.realpath(__file__))
test_data_path = os.path.join(current_test_path, 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_multi_agent_protocols_communication.yaml')

# Set configuration
parameters = [
    {'PROTOCOL': TCP, 'PORT': 1514},
    {'PROTOCOL': TCP, 'PORT': 56000},
    {'PROTOCOL': UDP, 'PORT': 1514},
    {'PROTOCOL': UDP, 'PORT': 56000},
    {'PROTOCOL': TCP_UDP, 'PORT': 1514},
    {'PROTOCOL': TCP_UDP, 'PORT': 56000}
]

metadata = [
    {'protocol': TCP, 'port': 1514},
    {'protocol': TCP, 'port': 56000},
    {'protocol': UDP, 'port': 1514},
    {'protocol': UDP, 'port': 56000},
    {'protocol': TCP_UDP, 'port': 1514},
    {'protocol': TCP_UDP, 'port': 56000}
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


def validate_agent_manager_protocol_communication(manager_port, protocol, num_agents=2):

    def send_event(event, protocol, manager_port):
        sender = ag.Sender(agent_info['manager_address'], protocol=protocol, manager_port=manager_port)

        try:
            sender.send_event(event)
        finally:
            sender.socket.close()

    send_event_threads = []
    search_patterns = []

    # Create num_agents (parameter) agents
    agents = ag.create_agents(agents_number=num_agents, manager_address=agent_info['manager_address'],
                              agents_version=agent_info['version'],agents_os= agent_info['os'],
                              disable_all_modules=agent_info['disable_all_modules'])

    for idx, agent in enumerate(agents):
        if protocol == TCP_UDP:
            # Round robin to select the protocol
            protocol = TCP if idx % 2 == 0 else UDP

        # Generate custom events for each agent
        search_pattern = f"test message from agent {agent.id}"
        agent_custom_message = f"1:/test.log:Feb 23 17:18:20 manager sshd[40657]: {search_pattern}"
        event = agent.create_event(agent_custom_message)

        # Save the search pattern to check it later
        search_patterns.append(search_pattern)

        # Create sender event threads
        send_event_threads.append(ThreadExecutor(send_event, {'event': event, 'protocol': protocol,
                                                              'manager_port': manager_port}))

    # Create socket monitor thread and start it
    socket_monitor_thread = ThreadExecutor(rd.check_queue_socket_event, {'raw_events': search_patterns})
    socket_monitor_thread.start()

    # Wait 3 seconds until socket monitor is fully initialized
    sleep(3)

    # Start sender event threads
    for thread in send_event_threads:
        thread.start()

    # Wait until sender event threads finish
    for thread in send_event_threads:
        thread.join()

    # Wait until socket monitor thread finishes
    socket_monitor_thread.join()


# Fixtures
@pytest.fixture(scope='module', params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_multi_agents_protocols_communication(get_configuration, configure_environment, restart_remoted):
    """Validate agent-manager communication using different protocols and ports"""
    manager_port = get_configuration['metadata']['port']
    protocol = get_configuration['metadata']['protocol']

    validate_agent_manager_protocol_communication(manager_port, protocol)
