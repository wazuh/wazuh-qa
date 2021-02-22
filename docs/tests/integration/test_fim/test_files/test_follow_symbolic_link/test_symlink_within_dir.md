# Test change target

Check the precedence of monitoring options when there is a symbolic link within monitored directory and `follow_symbolic_link` is enabled.
## General info

| Tier | Platforms | Time spent| Test file |
|:--:|:--:|:--:|:--:|
| 1 | Linux | 00:01:00 | [test_symlink_within_dir.py](../../../../../../tests/integration/test_fim/test_files/test_follow_symbolic_link/ test_symlink_within_dir.py)|

## Test logic

- The test will create a directory, a subdirectory and a symbolic link to the subdirectory. The directory and the symbolic link are monitored with different options.
- Then, it will generate events inside the directory and will check the alerts fields matches the ones that are configured for the directory.
- Finally, the test will generate events in the subdirectory and check the alerts fields matches the ones that are configured for the link.
## Checks

- [x] FIM processes correctly the precedence in the configuration when a symbolic link is inside a monitored directory.

## Execution result

```
python3 -m pytest test_files/test_follow_symbolic_link/test_symlink_within_dir.py
======================================================= test session starts ========================================================
platform linux -- Python 3.8.5, pytest-6.2.2, py-1.10.0, pluggy-0.13.1
rootdir: /vagrant/wazuh-qa/tests/integration, configfile: pytest.ini
plugins: html-2.0.1, testinfra-5.0.0, metadata-1.11.0
collected 3 items

test_files/test_follow_symbolic_link/test_symlink_within_dir.py ...                                                          [100%]

======================================================== 3 passed in 39.55s ========================================================
```

## Code documentation

::: tests.integration.test_fim.test_files.test_follow_symbolic_link.test_symlink_within_dir
