import pytest
import os

import wazuh_testing.tools.agent_simulator as ag

from time import sleep
from wazuh_testing.tools.thread_executor import ThreadExecutor
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools import file
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing import remote as rd
from wazuh_testing import TCP, UDP



# Marks
pytestmark = pytest.mark.tier(level=0)

# Variables
current_test_path = os.path.dirname(os.path.realpath(__file__))
test_data_path = os.path.join(current_test_path, 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_multi_agent_protocols_communication.yaml')

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

# Set configuration
parameters = [
    {'PROTOCOL': 'tcp,udp', 'PORT': 1514},
    {'PROTOCOL': 'tcp,udp', 'PORT': 56000}
]

metadata = [
    {'protocol': 'tcp,udp', 'port': 1514},
    {'protocol': 'tcp,udp', 'port': 56000}
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


def validate_agent_manager_protocol_communication(manager_port, num_agents=2):
    def validate_communication(agent, protocol, manager_port):
        agent_custom_message = f"test message from agent {agent.id}"
        event = agent.create_event(f"1:/test.log:Feb 23 17:18:20 manager sshd[40657]: {agent_custom_message}")

        sender = ag.Sender(agent_info['manager_address'], protocol=protocol, manager_port=manager_port)

        try:
            print("Sending event...")
            sender.send_event(event)
            print("Waiting..")
            rd.check_queue_socket_event(agent_custom_message)
            print("Passed..")
        finally:
            print("Closing..")
            sender.socket.close()


    file.truncate_file(LOG_FILE_PATH)

    # Create two agents
    agents = ag.create_agents(agents_number=num_agents, manager_address=agent_info['manager_address'],
                              agents_version=agent_info['version'],agents_os= agent_info['os'],
                              disable_all_modules=agent_info['disable_all_modules'])

    threads = []

    for idx, agent in enumerate(agents):
        protocol = TCP if idx % 2 == 0 else UDP
        print(f"LAUNCHING {idx} THREAD")
        threads.append(ThreadExecutor(validate_communication, {'agent': agent, 'protocol': protocol,
                                                               'manager_port': manager_port}))
    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    print("Join")

# Fixtures
@pytest.fixture(scope='module', params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_protocols_communication(get_configuration, configure_environment, restart_remoted):
    """Validate agent-manager communication using different protocols and ports"""
    manager_port = get_configuration['metadata']['port']

    validate_agent_manager_protocol_communication(manager_port)
