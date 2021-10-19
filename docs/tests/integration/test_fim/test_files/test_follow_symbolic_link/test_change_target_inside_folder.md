# Test change target inside folder

Check if FIM stops detecting events from previous target when pointing to a new folder.
## General info

| Tier | Platforms | Time spent| Test file |
|:--:|:--:|:--:|:--:|
| 1 | Linux/UNIX | 10 | 00:02 | [test_change_target_inside_folder.py](../../../../../../tests/integration/test_fim/test_files/test_follow_symbolic_link/test_change_target_inside_folder.py)|

## Test logic

- The test will monitor a symbolic link pointing to a file/folder.
- Once FIM starts, the test will change the link's target to another file/folder inside a monitored folder.
- It will wait until the thread that checks the symbolic links updates the link's target.
- Finally, it will generate some events inside the new target and it will check that the events are triggered

## Checks

- [x] The events are triggered for all the link's targets
- [X] No events are triggered for all link's targets

## Execution result

```
python3 -m pytest test_files/test_follow_symbolic_link/test_change_target_inside_folder.py
===================================================== test session starts ======================================================
platform linux -- Python 3.8.5, pytest-6.2.2, py-1.10.0, pluggy-0.13.1
rootdir: /vagrant/wazuh-qa/tests/integration, configfile: pytest.ini
plugins: html-2.0.1, testinfra-5.0.0, metadata-1.11.0
collected 12 items

test_files/test_follow_symbolic_link/test_change_target_inside_folder.py .ss..ss..ss.                                    [100%]

=========================================== 6 passed, 6 skipped in 178.70s (0:02:58) ===========================================
```

## Code documentation

<!-- ::: tests.integration.test_fim.test_files.test_follow_symbolic_link.test_change_target_inside_folder -->
