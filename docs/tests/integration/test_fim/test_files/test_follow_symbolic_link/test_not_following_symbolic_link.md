# Test change target
Checks the behaviour when monitoring a link that points to a file or a directory with the option `follow_symbolic_link` disabled.

## General info

| Tier | Platforms | Time spent| Test file |
|:--:|:--:|:--:|:--:|
| 1 | Linux/UNIX | 00:02:00 | [test_not_following_symbolic_link.py](../../../../../../tests/integration/test_fim/test_files/test_follow_symbolic_link/test_not_following_symbolic_link.py)|

## Test logic

- The test will create some files in a non monitored folder and won't expect any events.
- Then it will create a symbolic link inside a monitored folder and pointing to the non monitored folder.
- It will expect a `added` event with the path of the symbolic link, as it within a monitored directory.
- It will create some events in the symbolic link's target and won't expect any events.
- Then it will change the link's target, and it will expect a `modified` event.

## Checks

- [x] FIM doesn't monitor the link's target when `follow_symbolic_link` is disabled.
## Execution result

```
python3 -m pytest test_files/test_follow_symbolic_link/test_not_following_symbolic_link.py
============================= test session starts ==============================
platform linux -- Python 3.8.5, pytest-6.2.2, py-1.10.0, pluggy-0.13.1
rootdir: /vagrant/wazuh-qa/tests/integration, configfile: pytest.ini
plugins: html-2.0.1, testinfra-5.0.0, metadata-1.11.0
collected 6 items

test_files/test_follow_symbolic_link/test_not_following_symbolic_link.py . [ 16%]
.....                                                                                                        [100%]

=========================================== 6 passed in 87.60s (0:01:27) ===========================================
```

## Code documentation

<!-- ::: tests.integration.test_fim.test_files.test_follow_symbolic_link.test_not_following_symbolic_link -->
