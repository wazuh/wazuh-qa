'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: end_to_end

brief: This test will verify that the integeration with Virustotal works correctly. Syscheck scans a directory for
       changes and make the wazuh-integratord component query VirusTotal for threat results using the VirusTotal API.
       Once VirusTotal identifies a file as a threat, Wazuh is configured to trigger an active response to remove the
       file from the system.

components:
    - syscheck
    - integration
    - active_response

targets:
    - manager
    - agent

daemons:
    - wazuh-syscheckd
    - wazuh-integratord
    - wazuh-execd
    - wazuh-analysisd

os_platform:
    - linux

os_version:
    - CentOS 8

references:
    - https://github.com/wazuh/wazuh-automation/wiki/Wazuh-demo:-Execution-guide#-virustotal
    - https://documentation.wazuh.com/current/proof-of-concept-guide/detect-remove-malware-virustotal.html
    - https://documentation.wazuh.com/current/user-manual/capabilities/virustotal-scan/index.html#virustotal-scan

tags:
    - demo
    - virustotal
    - active_response
'''
import os
import json
import re
import pytest
from tempfile import gettempdir

from wazuh_testing import end_to_end as e2e
from wazuh_testing import event_monitor as evm
from wazuh_testing.tools import configuration as config


alerts_json = os.path.join(gettempdir(), 'alerts.json')
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
test_cases_file_path = os.path.join(test_data_path, 'test_cases', 'cases_virustotal_integration.yaml')
configuration_playbooks = ['configuration.yaml']
events_playbooks = ['generate_events.yaml']
teardown_playbooks = ['teardown.yaml']
remove_threat_file_path = os.path.join(test_data_path, 'active_response_script', 'remove-threat.sh')
configuration_extra_vars = {'active_response_script': remove_threat_file_path}

configurations, configuration_metadata, cases_ids = config.get_test_cases_data(test_cases_file_path)


@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
@pytest.mark.parametrize('metadata', configuration_metadata, ids=cases_ids)
def test_virustotal_integration(configure_environment, metadata, get_indexer_credentials, get_manager_ip,
                                generate_events, clean_alerts_index):
    '''
    description: Check that an alert is generated and the active response executed if the file is malicious.

    test_phases:
        - Set a custom Wazuh configuration.
        - Add a file to generate the event.
        - Check in the alerts.json log that the expected alert has been triggered and get its timestamp.
        - Check that the obtained alert from alerts.json has been indexed.

    wazuh_min_version: 4.4.0

    tier: 0

    parameters:
        - configurate_environment:
            type: fixture
            brief: Set the wazuh configuration according to the configuration playbook.
        - metadata:
            type: dict
            brief: Wazuh configuration metadata.
        - get_indexer_credentials:
            type: fixture
            brief: Get the wazuh indexer credentials.
        - generate_events:
            type: fixture
            brief: Generate events that will trigger the alert according to the generate_events playbook.
        - clean_alerts_index:
            type: fixture
            brief: Delete obtained alerts.json and alerts index.

    assertions:
        - Verify that the alert has been triggered.
        - Verify that the same alert has been indexed.

    input_description:
        - The `configuration.yaml` file provides the module configuration for this test.
        - The `generate_events.yaml`file provides the function configuration for this test.
    '''
    rule_id = metadata['rule.id']
    rule_level = metadata['rule.level']
    rule_description = metadata['rule.description']
    timestamp_regex = r'\d+-\d+-\d+T\d+:\d+:\d+\.\d+[+|-]\d+'

    expected_alert_json = fr'\{{"timestamp":"({timestamp_regex})","rule"\:{{"level"\:{rule_level},' \
                          fr'"description"\:"{rule_description}","id"\:"{rule_id}".*\}}'

    expected_indexed_alert = fr'.*"rule":.*"level": {rule_level},.*"description": "{rule_description}"' \
                             fr'.*"id": "{rule_id}".*"timestamp": "({timestamp_regex})".*'

    # Check that alert has been raised and save timestamp
    raised_alert = evm.check_event(callback=expected_alert_json, file_to_monitor=alerts_json,
                                   error_message='The alert has not occurred').result()
    raised_alert_timestamp = raised_alert.group(1)

    query = e2e.make_query([
        {
           "term": {
              "rule.id": f"{rule_id}"
           }
        },
        {
           "term": {
              "timestamp": f"{raised_alert_timestamp}"
           }
        },
    ])

    # Check if the alert has been indexed and get its data
    response = e2e.get_alert_indexer_api(query=query, credentials=get_indexer_credentials, ip_address=get_manager_ip)
    indexed_alert = json.dumps(response.json())

    # Check that the alert data is the expected one
    alert_data = re.search(expected_indexed_alert, indexed_alert)
    assert alert_data is not None, 'Alert triggered, but not indexed'
