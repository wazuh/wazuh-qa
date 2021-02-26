# Test change target

Check the FIM behavior when the option `follow_symbolic_link` is set to `no`.

## General info

| Tier | Platforms | Time spent| Test file |
|:--:|:--:|:--:|:--:|
| 1 | Linux/UNIX | 00:02:00 | [test_follow_symbolic_disabled.py](../../../../../../tests/integration/test_fim/test_files/test_follow_symbolic_link/test_follow_symbolic_disabled.py)|

## Test logic

- The test will monitor a symbolic link pointing to a file/directory.
- Once FIM starts, it will create and won't expect events inside the pointed folder.
- Then, the test will modify the link's target, and check that no alerts are triggered.
- Finally, the test will remove the link's target, and check that no alerts are triggered.
## Checks

- [x] FIM stops monitoring the link's target if the option `follow_symbolic_link` is disabled.

## Execution result

```
python3 -m pytest test_files/test_follow_symbolic_link/test_follow_symbolic_disabled.py
===================================================== test session starts ======================================================
platform linux -- Python 3.8.5, pytest-6.2.2, py-1.10.0, pluggy-0.13.1
rootdir: /vagrant/wazuh-qa/tests/integration, configfile: pytest.ini
plugins: html-2.0.1, testinfra-5.0.0, metadata-1.11.0
collected 12 items

test_files/test_follow_symbolic_link/test_follow_symbolic_disabled.py .ss..ss..ss.                                       [100%]

=========================================== 6 passed, 6 skipped in 95.89s (0:01:35) ============================================
```

## Code documentation

<!-- ::: tests.integration.test_fim.test_files.test_follow_symbolic_link.test_follow_symbolic_disabled -->
