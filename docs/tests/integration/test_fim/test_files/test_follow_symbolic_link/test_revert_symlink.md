# Test change target

Check if FIM detects changes in the symbolic links targets properly.

## General info

| Tier | Platforms | Time spent| Test file |
|:--:|:--:|:--:|:--:|
| 1 | Linux/UNIX | 00:02:00 | [test_revert_symlink.py](../../../../../../tests/integration/test_fim/test_files/test_follow_symbolic_link/test_revert_symlink.py)|

## Test logic

- The test will create a link to a file/directory.
- Then, it will change the target to a directory and will create some files inside, expecting all the alerts.
- After the events are processed, the test will change the link to it's previous target.
- The test will generate events and expect alerts.
## Checks

- [x] FIM monitors the target of the link when is changed and when the change is reverted.

## Execution result

```
python3 -m pytest test_files/test_follow_symbolic_link/test_revert_symlink.py
=============================================== test session starts ================================================
platform linux -- Python 3.8.5, pytest-6.2.2, py-1.10.0, pluggy-0.13.1
rootdir: /vagrant/wazuh-qa/tests/integration, configfile: pytest.ini
plugins: html-2.0.1, testinfra-5.0.0, metadata-1.11.0
collected 3 items

test_files/test_follow_symbolic_link/test_revert_symlink.py ...                                              [100%]

========================================== 3 passed in 159.54s (0:02:39) ===========================================
```

## Code documentation

::: tests.integration.test_fim.test_files.test_follow_symbolic_link.test_revert_symlink
