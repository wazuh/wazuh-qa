'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: end_to_end

brief: This test will verify that the use of lists in the rules and active response works correctly.

components:
    - logcollector
    - active_response

targets:
    - manager
    - agent

daemons:
    - wazuh-logcollector
    - wazuh-execd
    - wazuh-analysisd

os_platform:
    - linux
    - windows

os_version:
    - CentOS 8
    - Windows Server 2019

references:
    - https://github.com/wazuh/wazuh-automation/wiki/Wazuh-demo:-Execution-guide#ip_reputation
    - https://documentation.wazuh.com/current/proof-of-concept-guide/block-malicious-actor-ip-reputation.html
tags:
    - demo
    - ip_reputation
    - lists
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
test_cases_file_path = os.path.join(test_data_path, 'test_cases', 'cases_ip_reputation.yaml')
configuration_playbooks = ['configuration.yaml']
events_playbooks = ['generate_events.yaml']
teardown_playbooks = ['teardown.yaml']

configurations, configuration_metadata, cases_ids = config.get_test_cases_data(test_cases_file_path)


@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
@pytest.mark.parametrize('metadata', configuration_metadata, ids=cases_ids)
def test_ip_reputation(configure_environment, metadata, get_dashboard_credentials, get_manager_ip, generate_events,
                       clean_alerts_index):
    '''
    description: Check that alerts are generated when accessing the web server with an ip with a bad reputation.

    test_phases:
        - Set a custom Wazuh configuration.
        - Execute a request to the web server to generate the event.
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
    malicious_ip_alert = metadata['malicious_ip']
    active_response_alert = metadata['active_response']
    expected_alerts = [malicious_ip_alert, active_response_alert]
    timestamp_regex = r'\d+-\d+-\d+T\d+:\d+:\d+\.\d+[+|-]\d+'

    for alert in expected_alerts:
        rule_level = alert['rule.level']
        rule_id = alert['rule.id']
        rule_description = alert['rule.description']

        expected_alert_json = fr'\{{"timestamp":"({timestamp_regex})",' \
                              fr'"rule"\:{{"level"\:{rule_level},' \
                              fr'"description"\:"{rule_description}","id"\:"{rule_id}".*\}}'

        expected_indexed_alert = fr'.*"rule":.*"level": {rule_level},' \
                                 fr'.*"description": "{rule_description}"' \
                                 fr'.*"id": "{rule_id}".*'\
                                 fr'"timestamp": "({timestamp_regex})".*'

        # Check that alert has been raised and save timestamp
        raised_alert = evm.check_event(callback=expected_alert_json, file_to_monitor=alerts_json,
                                       timeout=fw.T_5, error_message=f"The alert '{rule_description}'"
                                                                     ' has not occurred').result()
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
            }
        ])

        # Check if the alert has been indexed and get its data
        response = e2e.get_alert_indexer_api(query=query, credentials=get_dashboard_credentials,
                                             ip_address=get_manager_ip)
        indexed_alert = json.dumps(response.json())

        # Check that the alert data is the expected one
        alert_data = re.search(expected_indexed_alert, indexed_alert)
        assert alert_data is not None, f"Alert '{rule_description}' triggered, but not indexed"
