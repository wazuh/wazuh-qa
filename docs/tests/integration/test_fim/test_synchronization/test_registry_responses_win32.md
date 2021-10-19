# Test registry responses win32

This test performs several tests that check if the registry synchronization is performed properly.

The test checks that if a modification occurs when the Windows agent is down, the synchronization is triggered with the new values.


## General info

| Tier | Platforms | Time spent| Test file |
|:--:|:--:|:--:|:--:|
| 1 | Windows | 00:02:00 | [test_registry_responses.py](../../../../../../tests/integration/test_fim/test_synchronization/test_registry_responses_win32.py)|

## Test logic


- First, the test will remove any monitored key and restart the agent. This removes the entry of the key used for the test from the manager's database.
- The test waits until the first synchronization is completed.
- Then, the test stops the Windows agent and creates key and values inside a monitored key.
- Finally, the test starts the agent and will check that the synchronization is performed with the new values.

## Checks

- [x] Check that FIM perform the registry synchronization when changes occurs while the agent is down.
- [x] Check that FIM perform properly the registry synchronization when using keys/values starting with `:`.
- [x] Check that FIM perform properly the registry synchronization when using keys/values ending with `:`.
- [x] Check that FIM perform properly the registry synchronization when using keys/values starting and ending with `:`.

## Execution result

```
python -m pytest test_synchronization\test_registry_responses_win32.py
================================================= test session starts =================================================
platform win32 -- Python 3.7.3, pytest-5.1.2, py-1.8.0, pluggy-0.13.0
rootdir: C:\Users\jmv74211\Desktop\wazuh-qa\tests\integration, inifile: pytest.ini
plugins: html-2.0.1, metadata-1.11.0, testinfra-5.0.0
collected 9 items

test_synchronization\test_registry_responses_win32.py .........                                                  [100%]

============================================ 9 passed in 137.78s (0:02:17) ============================================
```

## Code documentation

::: tests.integration.test_fim.test_synchronization.test_registry_responses_win32
