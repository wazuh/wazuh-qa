# Test change target with nested directory

This test checks that FIM doesn't trigger any alerts for directories within the target of a monitored symbolic link when the link is changed.

## General info

| Tier | Platforms | Time spent| Test file |
|:--:|:--:|:--:|:--:|
| 1 | Linux/UNIX | 00:00:30 | [test_change_target_with_nested_directory.py](../../../../../../tests/integration/test_fim/test_files/test_follow_symbolic_link/test_change_target_with_nested_directory.py)|

## Test logic

- The test will monitor a symbolic link pointing to a directory which contains a monitored subdirectory
- Once FIM starts, it will create and expect events inside the pointed folder.
- After the events are processed, the test will change the target of the link to another folder, it will wait until the thread that checks the symbolic links updates the link's target.
- Finally, it checks that no events are triggered inside the monitored subdirectory.

## Checks

- [x] No events are triggered inside the monitored subdirectory.

## Execution result

```
python3 -m pytest test_files/test_follow_symbolic_link/test_change_target_with_nested_directory.py
===================================================== test session starts ======================================================
platform linux -- Python 3.8.5, pytest-6.2.2, py-1.10.0, pluggy-0.13.1
rootdir: /vagrant/wazuh-qa/tests/integration, configfile: pytest.ini
plugins: html-2.0.1, testinfra-5.0.0, metadata-1.11.0
collected 1 item

test_files/test_follow_symbolic_link/test_change_target_with_nested_directory.py .                                       [100%]

====================================================== 1 passed in 27.86s ======================================================
```

## Code documentation

<!-- ::: tests.integration.test_fim.test_files.test_follow_symbolic_link.test_change_target_with_nested_directory -->
