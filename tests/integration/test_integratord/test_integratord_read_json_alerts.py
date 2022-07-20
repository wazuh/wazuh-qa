'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
type: integration
brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts
       when these files are modified. In particular, these tests will check if FIM changes
       the monitoring mode from 'realtime' to 'scheduled' when it is not supported.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured
       files for changes to the checksums, permissions, and ownership.
components:
    - fim
suite: files_basic_usage
targets:
    - agent
daemons:
    - wazuh-syscheckd
os_platform:
    - macos
    - solaris
os_version:
    - macOS Catalina
    - macOS Server
    - Solaris 10
    - Solaris 11
references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html
pytest_args:
    - fim_mode:
        realtime: Enable real-time monitoring on Linux (using the 'inotify' system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the 'who-data' information.
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.
tags:
    - fim_basic_usage
'''
import os
import pytest
from wazuh_testing import global_parameters
from wazuh_testing.tools import WAZUH_PATH, LOG_FILE_PATH
from wazuh_testing.tools.file import truncate_file, write_file
from wazuh_testing.tools.configuration import get_test_cases_data, load_configuration_template
from wazuh_testing.tools.monitoring import FileMonitor, callback_generator


# Marks
pytestmark = [pytest.mark.server]

# Reference paths
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, 'configuration_template')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases')

# Configuration and cases data
configurations_path = os.path.join(CONFIGURATIONS_PATH, 'config_integratord_read_json_alerts.yaml')
cases_path = os.path.join(TEST_CASES_PATH, 'cases_integratord_read_json_alerts.yaml')

# Configurations
configuration_parameters, configuration_metadata, case_ids = get_test_cases_data(cases_path)
configurations = load_configuration_template(configurations_path, configuration_parameters,
                                                configuration_metadata)
local_internal_options = {'integrator.debug': '2', 'syscheck.debug':'2'}

# Variables
JSON_LOG_FILE = os.path.join(WAZUH_PATH, 'logs/alerts/alerts.json')



# Tests
@pytest.mark.tier(level=1)
@pytest.mark.parametrize('configuration, metadata',
                         zip(configurations, configuration_metadata), ids=case_ids)
def test_integratord_read_json_alerts(configuration, metadata,
                              configure_local_internal_options_module,restart_wazuh_function):
    '''
    description: Check if the current OS platform falls to the 'scheduled' mode when 'realtime' is not available.
                 For this purpose, the test performs a CUD set of operations to a file with 'realtime' mode set as
                 the monitoring option in the 'ossec.conf' file. Firstly it checks for the initial 'realtime' event
                 appearing in the logs, and if the current OS does not support it, wait for the initial FIM scan
                 mode. After this, the set of operations takes place and the expected behavior is the events will be
                 generated with 'scheduled' mode and not 'realtime' as it is set in the configuration.
    wazuh_min_version: 4.2.0
    tier: 0
    parameters:
        - configure_local_internal_options_module:
            type: fixture
            brief: Configure the local internal options file.
    assertions:
        - Verify that FIM changes the monitoring mode from 'realtime' to 'scheduled' when it is not supported.
    input_description: A test case (ossec_conf) is contained in external YAML file (wazuh_conf_check_realtime.yaml)
                       which includes configuration settings for the 'wazuh-syscheckd' daemon and, it is combined
                       with the testing directory to be monitored defined in this module.
    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added', 'modified' and 'deleted' events)

    '''
    sample = metadata['alert_sample']
    wazuh_monitor = FileMonitor(LOG_FILE_PATH)
    if metadata['alert_type'] == 'valid':
        callback = '.*VirusTotal: Alert - .*integration\":\"virustotal\".*'
        wazuh_monitor = FileMonitor(JSON_LOG_FILE)
    elif metadata['alert_type'] == 'invalid':
        callback = '.*wazuh-integratord.*WARNING: Invalid JSON alert read.*'
    elif metadata['alert_type'] == 'overlong':
        padding = "0"*90000
        sample = sample.replace("padding_input","agent_"+padding)
        callback = '.*wazuh-integratord.*WARNING: Overlong JSON alert read.*'
    elif metadata['alert_type'] == 'inode_changed':
        callback = '.*wazuh-integratord.*DEBUG: jqueue_next\(\): Alert file inode changed.*'
    
    # Insert custom Alert   
    os.system(f"echo '{sample}' >> {JSON_LOG_FILE}")
    
    # Read Response in ossec.log
    result = wazuh_monitor.start(timeout=global_parameters.default_timeout,
                            callback=callback_generator(callback),
                            error_message=metadata['error_message']).result()
