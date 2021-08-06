import os
import pytest

import wazuh_testing.remote as rd
import wazuh_testing.tools.agent_simulator as ag

from time import sleep
from wazuh_testing import TCP, UDP, TCP_UDP
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.thread_executor import ThreadExecutor



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


def validate_agent_manager_protocol_communication(num_agents=2, manager_port=1514, protocol=TCP):
    """Check the communication between the manager and several agents using different protocols and ports.

    Args:
        num_agents (int): Number of agents to send events and to validate the communication.
        manager_port (int): Manager remote communication port.
        protocol (str): It can be TCP, UDP or TCP_UDP (both).

    Raises:
        TimeoutError: If the event has not been found in the queue socket after the agents have been sent.
    """
    def send_event(event, protocol, manager_port, agent):
        """Send an event to the manager"""
        sender = ag.Sender(agent_info['manager_address'], protocol=protocol, manager_port=manager_port)
        injector = ag.Injector(sender=sender, agent=agent)
        injector.sender.send_event(event)
        return injector


    send_event_threads = []
    agent_custom_messages = []

    # Create num_agents (parameter) agents
    agents = ag.create_agents(agents_number=num_agents, manager_address=agent_info['manager_address'],
                              agents_version=[agent_info['version']]*num_agents,
                              agents_os=[agent_info['os']]*num_agents,
                              disable_all_modules=agent_info['disable_all_modules'])

    for idx, agent in enumerate(agents):
        if protocol == TCP_UDP:
            # Round robin to select the protocol
            protocol = TCP if idx % 2 == 0 else UDP

        # Generate custom events for each agent
        agent_custom_message = f"1:/test.log:Feb 23 17:18:20 manager sshd[40657]: test message from agent {agent.id}"
        event = agent.create_event(agent_custom_message)

        # Save the agent message to check it later
        agent_custom_messages.append(agent_custom_message)

        # Create sender event threads
        send_event_threads.append(ThreadExecutor(send_event, {'event': event, 'protocol': protocol,
                                                              'manager_port': manager_port, 'agent': agent}))

    # Create archives log monitor
    archives_monitor = rd.create_archives_log_monitor()

    # Wait 10 seconds until socket monitor is fully initialized
    sleep(10)

    # Start sender event threads
    for thread in send_event_threads:
        thread.start()

    # Wait until sender event threads finish
    for thread in send_event_threads:
        thread.join()

    # Monitor archives log to find the sent messages
    for message in agent_custom_messages:
        rd.detect_archives_log_event(archives_monitor,
                                     callback=rd.callback_detect_syslog_event(message),
                                     update_position=False,
                                     timeout=30,
                                     error_message="Agent message wasn't received or took too much time.")


# Fixtures
@pytest.fixture(scope='module', params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_multi_agents_protocols_communication(get_configuration, configure_environment, restart_remoted):
    """Validate agent-manager communication with several agents using different protocols and ports"""
    manager_port = get_configuration['metadata']['port']
    protocol = get_configuration['metadata']['protocol']

    validate_agent_manager_protocol_communication(manager_port=manager_port, protocol=protocol)
