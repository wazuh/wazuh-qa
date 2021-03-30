# test audit multiple keys
When an audit rule has more than one key, audit decodes the keys in hexadecimal. This test configures audit rules
for monitored and non monitored directories with more than one key, checks that FIM decodes properly the hexadecimal keys and makes sure that
if the directory is monitored, events are triggered.

| Tier | Platforms | Time spent| Test file |
|:--:|:--:|:--:|:--:|
| 1 | Linux | 00:01:00 | [test_audit_multiple_keys.py](../../../../../../tests/integration/test_fim/test_files/test_audit/test_audit_multiple_keys.py)|

## Test logic

- The test creates audit rules with multiple keys for monitored and non monitored directories
- Then it waits until FIM reloads the audit rules. This is to avoid false positives when `whodata healthcheck` events remains in the audit socket.
- It creates files inside the specified folder and check if FIM decodes the key of the audit event.
- If the action was performed in a monitored directory, check that the event is triggered.

## Checks

- [x] FIM decodes audit events with multiple keys.

## Execution result

```
python3 -m pytest test_files/test_audit/test_audit_multiple_keys.py
==================================================================== test session starts ====================================================================
platform linux -- Python 3.8.5, pytest-6.2.2, py-1.10.0, pluggy-0.13.1
rootdir: /vagrant/wazuh-qa/tests/integration, configfile: pytest.ini
plugins: html-2.0.1, testinfra-6.2.0, testinfra-6.0.0, metadata-1.11.0
collected 2 items

test_files/test_audit/test_audit_multiple_keys.py ..                                                                                                  [100%]

=============================================================== 2 passed in 66.54s (0:01:06) ================================================================

```

## Code documentation

::: tests.integration.test_fim.test_files.test_audit.test_audit_multiple_keys
