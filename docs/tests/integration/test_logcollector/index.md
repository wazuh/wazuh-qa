# Overview

`Logcollector` is the daemon that receives logs through text files or Windows event logs. It can also
directly receive logs via remote Syslog which is useful for 
firewalls and other such devices. In the case of the Windows agent, `wazuh-agent` is the one who collects these 
logs and send them to the manager.

## Tiers
### Tier 0
#### Test configuration

For each configuration option, we check if `logcollector` and `agentd` correctly
starts and that any API request to the Manager configuration returns the same options that the specified 
in configuration file.

#### Test command monitoring

Command monitoring consists of periodically executing programs and logging their output to detect 
possible changes in it. These tests will verify that the `logcollector` command monitoring system works 
correctly by running different commands with special characteristics.

#### Test keep running

This test will check if `logcollector` keeps running once a log is rotated 
(move the data to another file and empty the file that is being monitored).