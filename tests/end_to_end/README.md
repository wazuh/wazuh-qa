# E2E tests

End-to-end testing is a technique that tests the entire software product from beginning to end to ensure the application flow behaves as expected.

The main purpose of End-to-end (E2E) testing is to test from the end user’s experience by simulating the real user scenario and validating the system under test and its components for integration and data integrity.

The Wazuh architecture is based on agent, running on the monitored endpoints, that forward security data to a central server. The central server decodes and analyzes the incoming information and passes the results along to the Wazuh indexer for indexing and storage. The Wazuh indexer cluster is a collection of one or more nodes that communicate with each other to perform read and write operations on indices.

The diagram below represents the Wazuh components and data flow.

![wazuh-data-flow](https://documentation.wazuh.com/current/_images/data-flow1.png)


Our E2E tests will verify that, after generating an event, an alert will be triggered and correctly indexed.

## Setting up a test environment

To run these tests we need to use a **Linux** machine and install the following tools:

- [Ansible](https://docs.ansible.com/ansible/latest/installation_guide/intro_installation.html)

Then, you will need to have an inventory with the needed hosts and variables. For example:

```
manager:
  hosts:
    centos-manager:
      ansible_host: <IP_ADDRESS>
      ansible_connection: ssh
      ansible_user: <USER>
      ansible_ssh_private_key_file: <PRIVATE_KEY>
      ansible_python_interpreter: /usr/bin/python3
      dashboard_user: <DASHBOARD_USER>
      dashboard_password: <DASHBOARD_PASSWORD>

agent:
  children:
    linux:
      hosts:
        ubuntu-agent:
          ansible_host: <IP_ADDRESS>
          ansible_connection: ssh
          ansible_user: <USER>
          ansible_ssh_private_key_file: <PRIVATE_KEY>
          ansible_python_interpreter: /usr/bin/python3
        centos-agent:
          ansible_host: <IP_ADDRESS>
          ansible_connection: ssh
          ansible_user: <USER>
          ansible_ssh_private_key_file: <PRIVATE_KEY>
          ansible_python_interpreter: /usr/bin/python3
    windows:
      hosts:
        windows-agent:
          ansible_host: <IP_ADDRESS>
          ansible_user: <USER>
          ansible_password: <PASSWORD>
          ansible_connection: winrm
          ansible_winrm_server_cert_validation: ignore
          ansible_winrm_transport: basic
          ansible_winrm_port: 5985 (Only in local executions)
          ansible_python_interpreter: C:\Users\vagrant\AppData\Local\Programs\Pyhton\Python39\python.exe

all:
  vars:
    virustotal_key: <VIRUSTOTAL_KEY>
    bucket_name: <BUCKET_NAME>
    aws_region: <AWS_REGION>
    aws_access_key_id: <AWS_ACCESS_KEY>
    aws_secret_access_key: <AWS_SECRET_KEY>
    web_hook_url: <SLACK_WEB_HOOK_URL>
    slack_token: <SLACK_TOKEN>
    slack_channel: <SLACK_CHANNEL>
    s3_url: <S3_URL> (Should be always present)

```

Variables required by the tests:

- **test_aws_infrastructure_monitoring**:
    + bucket_name: <BUCKET_NAME>
    + aws_region: <AWS_REGION>
    + aws_access_key_id: <AWS_ACCESS_KEY>
    + aws_secret_access_key: <AWS_SECRET_KEY>

- **test_slack_integration**:
    + web_hook_url: <SLACK_WEB_HOOK_URL>
    + slack_token: <SLACK_TOKEN>
    + slack_channel: <SLACK_CHANNEL>

- **test_virustotal_integration**:
    + virustotal_key: <VIRUSTOTAL_KEY>

> Note: For the Emotet test, the Windows machine must have Office installed.

## E2E tests

**DISCLAIMER:** this guide assumes you have a proper testing environment. If you do not, please check
our [testing environment guide](#setting-up-a-test-environment).

Our newest integration tests are located in `wazuh-qa/tests/end_to_end/test_basic_cases`:

- _test_audit_
- _test_aws_infrastructure_monitoring_
- _test_brute_force_
- _test_detecting_suspicious_binaries_
- _test_docker_monitoring_
- _test_emotet_
- _test_fim_
- _test_ip_reputation_
- _test_osquery_integration_
- _test_shellshock_attack_detection_
- _test_slack_integration_
- _test_sql_injection_
- _test_suricata_integration_
- _test_unauthorized_processes_detection_
- _test_virustotal_integration_
- _test_vulnerability_detector_
- _test_windows_defender_
- _test_yara_integration_

Every group will have the following structure:

```bash
├── test_<basic_case>
│   ├── data
│   │   ├── playbooks
│   │   │   ├── <wazuh_conf>.yaml
│   │   │   └── <wazuh_conf>.yaml
│   │   ├── test_cases
│   │   │   └── <cases>.yaml
└── └── └── test_<module>.py
```

Audit test structure example:

```bash
test_basic_cases/
└── test_audit/
    ├── data/
    │   ├── playbooks/
    │   │   ├── configuration.yaml
    │   │   ├── generate_events.yaml
    │   │   └── teardown.yaml
    │   └── test_cases/
    │       └── cases_audit.yaml
    └── test_audit.py
```

### Tests execution

To execute these tests, we need to run the following command:

```
python -m pytest <TEST_PATH> --inventory_path=<INVENTORY_PATH>
```

#### Audit tests examples

```shell script
python3 -m pytest tests/end_to_end/test_basic_cases/test_audit/ --inventory_path=/home/juliamagan/Desktop/QA/2893/inventory.yml
======================================================================== test session starts ========================================================================
platform linux -- Python 3.9.7, pytest-6.2.2, py-1.10.0, pluggy-0.13.1
rootdir: /home/juliamagan/Desktop/QA/wazuh-qa
plugins: metadata-2.0.1, html-3.1.1, testinfra-5.0.0
collected 1 item

tests/end_to_end/test_basic_cases/test_audit/test_audit.py .                                                                                                  [100%]

======================================================================== 1 passed in 16.05s =========================================================================

```
