import pytest
import os
import threading

from wazuh_testing.tools.thread_executor import ThreadExecutor
import wazuh_testing.tools.agent_simulator as ag
from wazuh_testing.tools import LOG_FILE_PATH, ARCHIVES_LOG_FILE_PATH
from wazuh_testing.tools import file
from wazuh_testing.tools import monitoring
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing import remote as rd
from time import sleep

# Marks
pytestmark = pytest.mark.tier(level=0)

# Variables
current_test_path = os.path.dirname(os.path.realpath(__file__))
test_data_path = os.path.join(current_test_path, 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_agent_connection_protocols.yaml')

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
wazuh_archives_monitor = rd.create_archives_log_monitor()

# Set configuration
parameters = [
    {'PROTOCOL': 'tcp', 'PORT': 1514},
    {'PROTOCOL': 'udp', 'PORT': 1514},
    {'PROTOCOL': 'tcp,udp', 'PORT': 1514},
    {'PROTOCOL': 'udp,tcp', 'PORT': 1514},
    {'PROTOCOL': 'tcp', 'PORT': 56000},
    {'PROTOCOL': 'udp', 'PORT': 56000},
    {'PROTOCOL': 'tcp,udp', 'PORT': 56000},
    {'PROTOCOL': 'udp,tcp', 'PORT': 56000},
]

metadata = [
    {'protocol': 'tcp', 'port': 1514},
    {'protocol': 'udp', 'port': 1514},
    {'protocol': 'tcp,udp', 'port': 1514},
    {'protocol': 'udp,tcp', 'port': 1514},
    {'protocol': 'tcp', 'port': 56000},
    {'protocol': 'udp', 'port': 56000},
    {'protocol': 'tcp,udp', 'port': 56000},
    {'protocol': 'udp,tcp', 'port': 56000},
]

agent_info = {
    'server_address': '127.0.0.1',
    'os': 'debian7',
    'version': '4.2.0',
    'disable_all_modules': True
}

configuration_ids = [f"{item['PROTOCOL'].upper()}_{item['PORT']}" for item in parameters]

# Configuration data
configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)


def validate_agent_manager_protocol_communication(protocol, manager_port):
    """ Allow to validate if the agent-manager communication using a certain protocol has been successfull.

    For this purpose, two jobs are launched concurrently. One for monitoring the archives.log and one for sending the
    message.

    Args:
        protocol (str): Message sending protocol. It can be TCP or UDP.
        manager_port (int): Manager port when remoted is listening.

    Raises:
        TimeoutError: If the expected event could not be found in archives.log after sending it.
    """
    file.truncate_file(LOG_FILE_PATH)
    file.truncate_file(ARCHIVES_LOG_FILE_PATH)

    monitor_thread = ThreadExecutor(
        rd.detect_archives_log_event, {'archives_monitor': wazuh_archives_monitor, 'timeout': 20,
                                       'callback': rd.callback_detect_example_archives_event(),
                                       'update_position': False})

    send_message_thread = ThreadExecutor(rd.send_agent_event, {'wazuh_log_monitor': wazuh_log_monitor,
                                                               'protocol': protocol, 'manager_port': manager_port})
    # Start log monitoring
    monitor_thread.start()

    # Time to wait until starting the log monitoring
    sleep(2)

    # Send agent message
    send_message_thread.start()

    # Wait until the threads end
    monitor_thread.join()
    send_message_thread.join()


# Fixtures
@pytest.fixture(scope='module', params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_agent_connection_protocols(get_configuration, configure_environment, restart_remoted):
    protocol = get_configuration['metadata']['protocol']
    manager_port = get_configuration['metadata']['port']

    if protocol in ['udp,tcp', 'tcp,udp']:
        validate_agent_manager_protocol_communication(rd.TCP, manager_port)
        validate_agent_manager_protocol_communication(rd.UDP, manager_port)
    else:
        validate_agent_manager_protocol_communication(protocol, manager_port)
