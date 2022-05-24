'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
type: e2e
brief: Wazuh includes a registration process that provides the user with an automated mechanism to enroll agents with
       minimal configuration steps. To register an agent using the enrollment method, a manager with a valid IP needs
       to be configured first. The agent then checks for the registration key in the client.keys file, and when the file
       is empty, it automatically requests the key from the configured manager the agent is reporting to.

'''

import paramiko
import pytest
from opensearchpy import OpenSearch
import yaml
import datetime
import time


@pytest.fixture
def configurations():
    yaml_file_path = 'data/config.yml'
    with open(yaml_file_path) as stream:
        configurations = yaml.safe_load(stream)
    return configurations


def test_brute_force(configurations):
    """
    Test to detect a SSH Brute Force attack
    """
    ip_agent = configurations['wazuh-agent-linux'][0]['ip']
    agent_hostname = configurations['wazuh-agent-linux'][1]['hostname']
    rule_id = configurations['wazuh-agent-linux'][2]['rule_id']
    indexer_ip = configurations['wazuh-manager-indexer'][0]['ip']
    indexer_user = configurations['wazuh-manager-indexer'][2]['username_indexer']
    indexer_password = configurations['wazuh-manager-indexer'][3]['password_ indexer']

    current_time = datetime.datetime.utcnow()
    timestamp = current_time.timestamp()
    timestamp_formatted = time.strftime('%Y-%m-%dT%H:%M:%S.%3M+0000', time.localtime(timestamp))

    ssh = paramiko.SSHClient()

    for i in range(8):
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy)
        try:
            ssh.connect(hostname= ip_agent, username='test_user', password="test")
        except paramiko.AuthenticationException:
            print("Next connection")

    open_search_alerts = _get_opensearch_alert(indexer_ip, rule_id, indexer_user, indexer_password)
    _asserts(open_search_alerts, agent_hostname, timestamp_formatted)


def _get_opensearch_alert(indexer_ip, rule_id, username, password):
    """
    Get alert generated in opensearch
    """
    auth = (username, password)
    host = indexer_ip
    port = '9200'
    index_name = 'wazuh-alerts-4.x-*'
    rule_id = rule_id
    query = '{"query": {"bool": {"must": [{"term": {"rule.id": "' + rule_id + '"}}]}}, "size": 1, "sort": [{"timestamp": {"order": "desc"}}]}'

    client = OpenSearch(
        hosts= [{'host': host, 'port': port}],
        http_auth = auth,
        use_ssl = True,
        verify_certs = False,
        timeout = 30,
        max_retries = 10,
        retry_on_timeout = True

    )

    response = client.search(
        body = query,
        index= index_name
    )

    return response


def _asserts(response, agent_hostname, timestamp_test):
    agent = response['hits']['hits'][0]['_source']['agent']['name']
    description = response['hits']['hits'][0]['_source']['rule']['description']
    rule_id = response['hits']['hits'][0]['_source']['rule']['id']
    mitre_technique = response['hits']['hits'][0]['_source']['rule']['mitre']['technique'][0]
    timestamp = response['hits']['hits'][0]['_source']['timestamp']
    assert timestamp >= timestamp_test , 'Alert not generated'
    assert description == 'sshd: brute force trying to get access to the system.', 'Invalid description'
    assert rule_id == '5712', 'Invalid rule id'
    assert mitre_technique == 'Brute Force', 'Invalid mitre technique'
    assert agent == agent_hostname, 'Invalid agent'
