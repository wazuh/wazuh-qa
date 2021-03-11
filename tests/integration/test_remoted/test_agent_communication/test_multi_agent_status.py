import os
import pytest

from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing import remote as rd
from wazuh_testing import TCP_UDP


# Marks
pytestmark = pytest.mark.tier(level=2)

# Variables
current_test_path = os.path.dirname(os.path.realpath(__file__))
test_data_path = os.path.join(current_test_path, 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_multi_agent_status.yaml')

# Set configuration
parameters = [
    {'PROTOCOL': TCP_UDP, 'PORT': 56000},
    {'PROTOCOL': TCP_UDP, 'PORT': 1514},
]

metadata = [
    {'protocol': TCP_UDP, 'port': 56000},
    {'protocol': TCP_UDP, 'port': 1514},
]


configuration_ids = [f"{item['PROTOCOL'].upper()}_{item['PORT']}" for item in parameters]

# Configuration data
configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)


# Fixtures
@pytest.fixture(scope='module', params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_protocols_communication(get_configuration, configure_environment, restart_remoted):
    """Validate agent-manager communication using different protocols and ports"""
    manager_port = get_configuration['metadata']['port']

    rd.check_active_agents(num_agents=2, manager_port=manager_port)
