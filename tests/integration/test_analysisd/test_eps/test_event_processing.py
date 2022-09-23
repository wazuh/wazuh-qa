import os
import pytest
import threading
import time
from math import ceil

from wazuh_testing.tools.configuration import load_configuration_template, get_test_cases_data
from wazuh_testing.modules.analysisd import event_monitor as evm
from wazuh_testing.tools.services import control_service
from wazuh_testing.modules.analysisd import ANALYSISD_STATE_INTERNAL_DEFAULT
from wazuh_testing.processes import check_if_daemons_are_running
from wazuh_testing.tools.run_simulator import syslog_simulator
from wazuh_testing.tools.thread_executor import ThreadExecutor

# Reference paths
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, 'configuration_template', 'event_processing_test_module')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases', 'event_processing_test_module')
local_internal_options = {'wazuh_modules.debug': '2', 'monitord.rotate_log': '0',
                          'analysisd.state_interval': '1'}

# ------------------------------- TEST_LIMITATION ----------------------------------------------------------------------
# Configuration and cases data
t1_configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_limitation.yaml')
t1_cases_path = os.path.join(TEST_CASES_PATH, 'cases_limitation.yaml')

# Limitation test configurations (t1)
t1_configuration_parameters, t1_configuration_metadata, t1_case_ids = get_test_cases_data(t1_cases_path)
t1_configurations = load_configuration_template(t1_configurations_path, t1_configuration_parameters,
                                                t1_configuration_metadata)

@pytest.mark.tier(level=0)
@pytest.mark.parametrize('configuration, metadata', zip(t1_configurations, t1_configuration_metadata), ids=t1_case_ids)
def test_limitation(configuration, metadata, load_wazuh_basic_configuration,
                    set_wazuh_configuration, configure_local_internal_options_module,
                    truncate_monitored_files, restart_wazuh_daemon_function):
    # Set syslog simulator parameters according to the use case data
    syslog_simulator_parameters = {'address': metadata['address'], 'port': metadata['port'],
                                   'protocol': metadata['protocol'], 'eps': metadata['eps'],
                                   'messages_number': metadata['messages_number']}

    # Run syslog simulator thread
    syslog_simulator_thread = ThreadExecutor(syslog_simulator, {'parameters': syslog_simulator_parameters})
    syslog_simulator_thread.start()

    # Wait until syslog simulator is started
    time.sleep(1)

    # Get analysisd stats
    analysisd_state = evm.get_analysisd_state()
    events_received = int(analysisd_state['events_received'])
    events_processed = int(analysisd_state['events_processed'])

    # Check that wazuh-manager is processing syslog events
    assert events_received > 0, '(0): No events are being received when it is expected'
    assert events_processed > 0, 'No events are being processed when it is expected'

    # Wait until the limitation period has expired
    time.sleep(ceil((metadata['maximum'] * metadata['timeframe']) / metadata['eps']))

    # Get analysisd stats in limitation stage
    analysisd_state = evm.get_analysisd_state()
    events_received = int(analysisd_state['events_received'])
    events_processed = int(analysisd_state['events_processed'])

    # Check that the wazuh-manager is receiving events but it is not processing them due to the limitation
    assert events_received > 0, '(1): No events are being received when it is expected'
    assert events_processed == 0, f"Events are being processed when the limit has been reached. {events_processed} != 0"

    # Wait until syslog simulator ends
    syslog_simulator_thread.join()
