# Test max fd win rt
Test to check that the option `max_fd_win_rt` is working properly. This option limits the number of realtime file descriptors that FIM can open.

## General info

| Tier | Platforms | Time spent| Test file |
|:--:|:--:|:--:|:--:|
| 1 | Windows | 00:00:30 | [test_max_fd_rt.py](../../../../../../tests/integration/test_fim/test_files/test_inotify/test_max_fd_rt.py)|

## Test logic
- The test will set the limit to 2.
- FIM will be monitoring 4 folders, 2 of them are created before FIM starts.
- The test will remove the 2 existing folders and will create them again, and will check that events are triggered.
- The test will remove those 2 folders.
- Finally, the test will create 2 folders and will check that events are triggered.
## Checks

- [x] Checks that FIM properly counts the number of realtime file descriptor opened.
- [x] FIM decreases the counter when a monitored folder is removed.

## Execution result

```
PS C:\Users\Administrator\Desktop\wazuh-qa\tests\integration\test_fim\test_files> python -m pytest .\test_inotify\test_m
ax_fd_rt.py
================================================= test session starts =================================================
platform win32 -- Python 3.6.0, pytest-6.2.4, py-1.10.0, pluggy-0.13.1
rootdir: C:\Users\Administrator\Desktop\wazuh-qa\tests\integration, configfile: pytest.ini
plugins: html-2.0.1, metadata-1.11.0, testinfra-6.3.0, testinfra-6.0.0
collected 1 item

test_inotify\test_max_fd_rt.py .                                                                                 [100%]

================================================= 1 passed in 26.69s ==================================================
```

## Code documentation

::: tests.integration.test_fim.test_files.test_inotify.test_max_fd_rt
