# Test max fd win rt

## Overview
This test will check that the option `max_fd_win_rt` is working properly.
This option limits the number of realtime file descriptors that FIM can open.

## General info

| Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 1 | 1 | 00:00:30 |

## Expected behavior

The agent can add new folders to the monitoring if any folder is removed after the limit is reached.

## Testing

FIM will be monitoring 4 folders, 2 of them are created before FIM starts, setting the limit to two folders.

- Once FIM is started, the test will remove the 2 existing folders and will create them again, checking that events are triggered.
- The test will remove those 2 folders.
- Finally, the test will remove those two folders and will create other 2 folders and will check that events are triggered.
## Checks

- FIM detect changes when monitored folders are deleted and created again
- Fim detect changes on new folders

## Code documentation

::: tests.integration.test_fim.test_files.test_inotify.test_max_fd_rt
