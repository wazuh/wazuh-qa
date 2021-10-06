# Test macos log process 

## Overview 

Check `log stream` process has been killed when Wazuh agent or logcollector demon stops.

It has 3 testing functions:

#### test_independent_log_process

This method tests how an independent log process works when Wazuh starts and stops. It checks that, if a log process 
is launched before running Wazuh it doesn't stop working when Wazuh starts its own process or when it ends.

- Fail if the independent process dead after launching Wazuh or restarting it

#### test_macos_log_process_stop

This method checks that the log process is stopped when Wazuh agent or logcollector daemon stops.

- Fail if `log stream` process still running after `wazuh-agent` stops.
- Fail if `log stream` process still running after `wazuh-logcollector` stops.

#### test_macos_log_process_stop_suddenly_warning

This method tests what happens when the log process suddenly stops (for example, it is killed). Wazuh must log an error
in the ossec.log file

- Fail if that error doesn't appear in the logs


## Objective

- Check info/error messages when the log process exits while logcollector is still running.
- Check that log AND script processes are closed after the wazuh-agent closes (on macOS Sierra only).
- Check that log AND script processes are closed after the wazuh-logcollector closes (on macOS Sierra only).
- Check that log is closed when script is killed (on macOS Sierra only).
- Check that script is closed when log is killed (on macOS Sierra only).
- Check that independent execution of log processes (external to Wazuh) are not altered because of the Wazuh agent.

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 3 | 29s |


## Code documentation

::: tests.integration.test_logcollector.test_macos.test_macos_log_process
