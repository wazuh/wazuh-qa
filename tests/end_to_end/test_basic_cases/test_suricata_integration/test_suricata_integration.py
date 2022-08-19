'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: end_to_end

brief: This test will verify that the integeration with Suricata works correctly. Suricata is a network-based intrusion
       detection system (NIDS), to detect threats by monitoring network traffic. This solution can generate JSON logs
       of NIDS events and provide additional insight into your network's security with its network traffic inspection
       capabilities.

components:
    - logcollector
    - integration

targets:
    - manager
    - agent

daemons:
    - wazuh-logcollector
    - wazuh-analysisd

os_platform:
    - linux

os_version:
    - CentOS 8
    - Ubuntu Focal

references:
    - https://github.com/wazuh/wazuh-automation/wiki/Wazuh-demo:-Execution-guide#suricata
    - https://documentation.wazuh.com/current/proof-of-concept-guide/integrate-network-ids-suricata.html
    - https://documentation.wazuh.com/current/learning-wazuh/suricata.html#learning-wazuh-suricata
tags:
    - demo
    - suricata
    - nids
'''
import os
import json
import re
import pytest
from tempfile import gettempdir

import wazuh_testing as fw
from wazuh_testing import end_to_end as e2e
from wazuh_testing import event_monitor as evm
from wazuh_testing.tools import configuration as config


alerts_json = os.path.join(gettempdir(), 'alerts.json')
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
test_cases_file_path = os.path.join(test_data_path, 'test_cases', 'cases_suricata_integration.yaml')
configuration_playbooks = ['configuration.yaml']
events_playbooks = ['generate_events.yaml']
teardown_playbooks = ['teardown.yaml']

configurations, configuration_metadata, cases_ids = config.get_test_cases_data(test_cases_file_path)


@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
@pytest.mark.parametrize('metadata', configuration_metadata, ids=cases_ids)
def test_suricata_integration(configure_environment, metadata, get_dashboard_credentials, get_manager_ip,
                              generate_events, clean_alerts_index):
    '''
    description: Check that an alert is generated when a specific web request is executed.

    test_phases:
        - Set a custom Wazuh configuration.
        - Execute a web request known to trip NIDS rules to generate the event.
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
        - get_dashboard_credentials:
            type: fixture
            brief: Get the wazuh dashboard credentials.
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
    rule_level = metadata['rule.level']
    rule_description = metadata['rule.description']
    rule_id = metadata['rule.id']
    data_hostname = metadata['extra']['data.hostname']
    timestamp_regex = r'\d{4}-\d+-\d+T\d+:\d+:\d+\.\d+[+|-]\d+'

    expected_alert_json = fr".*timestamp.+({timestamp_regex}).+level.+{rule_level}.+description.+{rule_description}.+" \
                          fr"id.+{rule_id}.+hostname.+{data_hostname}"
    expected_indexed_alert = fr".*hostname.*{data_hostname}.+level.+{rule_level}.+description.+" \
                             fr"{rule_description}.+id.+{rule_id}"

    # Check that alert has been raised and save timestamp
    raised_alert = evm.check_event(callback=expected_alert_json, file_to_monitor=alerts_json,
                                   timeout=fw.T_5, error_message='The alert has not occurred').result()
    raised_alert_timestamp = raised_alert.group(1)

    query = e2e.make_query([
       {
          "term": {
             "rule.id": f"{rule_id}"
          }
       },
       {
          "term": {
             "rule.description": f"{rule_description}"
          }
       },
       {
          "term": {
             "timestamp": f"{raised_alert_timestamp}"
          }
       }
    ])

    # Check if the alert has been indexed and get its data
    response = e2e.get_alert_indexer_api(query=query, credentials=get_dashboard_credentials, ip_address=get_manager_ip)
    indexed_alert = json.dumps(response.json())

    # Check that the alert data is the expected one
    alert_data = re.search(expected_indexed_alert, indexed_alert)
    assert alert_data is not None, 'Alert triggered, but not indexed'
