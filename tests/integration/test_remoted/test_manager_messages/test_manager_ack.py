import pytest
import os

from wazuh_testing.tools.configuration import load_wazuh_configurations
import wazuh_testing.tools.agent_simulator as ag
from wazuh_testing import remote as rd

# Marks
pytestmark = pytest.mark.tier(level=1)

# Variables
current_test_path = os.path.dirname(os.path.realpath(__file__))
test_data_path = os.path.join(current_test_path, 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_manager_ack.yaml')

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

    # Create agent and sender object with default parameters
    agent = ag.Agent(**agent_info)
    sender = ag.Sender(agent_info['manager_address'], protocol=protocol)

    # Activate receives_messages modules in simulated agent.
    agent.set_module_status('receive_messages', 'enabled')

    # Run injector with only receive messages module enabled
    injector = ag.Injector(sender, agent)
    injector.run()

    # Send the start-up message
    sender.send_event(agent.startup_msg)

    # Check that the manager sends the ACK message
    event_monitor = 'todo'


# Fixtures
@pytest.fixture(scope='module', params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_manager_ack(get_configuration, configure_environment, restart_remoted):
    protocol = get_configuration['metadata']['protocol']

    if protocol in ['udp,tcp', 'tcp,udp']:
        check_manager_ack(rd.TCP)
        check_manager_ack(rd.UDP)
    else:
        check_manager_ack(protocol)
