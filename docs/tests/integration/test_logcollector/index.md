# Overview

`Logcollector` is the daemon that receives logs through text files or Windows event logs. It can also
directly receive logs via remote Syslog which is useful for 
firewalls and other such devices. In the case of the Windows agent, `wazuh-agent` is the one who collects these 
logs and send them to the manager.

## Tiers
### Tier 0
#### Test configuration

For each configuration option, we check if `logcollector` and `agentd` correctly
starts and that any API request to the Manager configuration returns the same options that the specified configuration file.

#### Test age

Ensure age option work as expected, ignoring files that have not been  modified for a time greater than age 
value using current date, even if datetime of the system changed while logcollector is running.
starts and that any API request to the Manager configuration returns the same options that the specified
in configuration file.

#### Test command monitoring

Command monitoring consists of periodically executing programs and logging their output to detect 
possible changes in it. These tests will verify that the `logcollector` command monitoring system works 
correctly by running different commands with special characteristics.

#### Test keep running

This test will check if `logcollector` keeps running once a log is rotated 
(move the data to another file and empty the file that is being monitored).

#### Test only future events

By default, when Wazuh starts it will only read the contents of the logs of a certain file since 
the agent was started, with the `only-future-events` option Wazuh can read these logs that were 
produced while the agent was stopped. 

#### Test location

For each location and exclude option specified in the configuration file, check if `logcollector` is analyzing or excluding the required files.

### Tier 1
#### Test location custom sockets

Wazuh allows forwarding the events that are written in a monitored log file to a UNIX `named socket` 
through the `target` option in the `localfile` section of the configuration. These tests will check 
if the statistics of the forwarded events, which are in the file `wazuh-logcollector.state` are correct, 
verifying that the dropped events match with the reported ones.