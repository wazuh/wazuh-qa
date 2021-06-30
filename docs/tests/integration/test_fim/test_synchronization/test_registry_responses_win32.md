# Test registry responses win32

This test performs several tests that check if the registry synchronization is performed properly.

The first test checks that synchronization is performed after changes after the baseline scan.
The second test checks that if a modification occurs when the Windows agent is down, the synchronization is triggered with the new values.


## General info

| Tier | Platforms | Time spent| Test file |
|:--:|:--:|:--:|:--:|
| 1 | Windows | 00:13:00 | [test_registry_responses.py](../../../../../../tests/integration/test_fim/test_synchronization/test_registry_responses_win32.py)|

## Test logic

### test_registry_responses
- The test waits for the baseline scan.
- Then, the test will create several sub-keys inside a monitored key and values inside the monitored key and the sub-keys.
- Finally, it will change the system clock and expect the synchronization event for the created keys/values.


### test_registry_sync_after_restart
- The test waits until the first synchronization is completed.
- Then, the test stops the Windows agent and creates values inside a monitored key.
- Finally, the test starts the agent and will check that the synchronization is performed with the new values.

## Checks

- [x] Check that FIM perform the registry synchronization after the baseline scan.
- [x] Check that FIM perform the registry synchronization when changes occurs while the agent is down.
- [x] Check that FIM perform properly the registry synchronization when using keys/values starting with `:`.
- [x] Check that FIM perform properly the registry synchronization when using keys/values ending with `:`.
- [x] Check that FIM perform properly the registry synchronization when using keys/values starting and ending with `:`.

## Execution result

```
python -m pytest test_synchronization\test_registry_responses_win32.py
=================================================================== test session starts ===================================================================
platform win32 -- Python 3.7.3, pytest-5.1.2, py-1.8.0, pluggy-0.13.0
rootdir: C:\Users\jmv74211\Desktop\wazuh-qa\tests\integration, inifile: pytest.ini
plugins: html-2.0.1, metadata-1.11.0, testinfra-5.0.0
collected 18 items
test_synchronization\test_registry_responses_win32.py s.................                                                                             [100%]

======================================================== 17 passed, 1 skipped in 808.74s (0:13:28) ========================================================
```

## Code documentation

::: tests.integration.test_fim.test_synchronization.test_registry_responses_win32
