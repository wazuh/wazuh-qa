# Overview

`Logcollector` is the daemon that receives logs through text files or Windows event logs. It can also
directly receive logs via remote syslog which is useful for 
firewalls and other such devices. In case of the Windows agent, the daemon in charge of this is task is
`agentd`

## Tiers
### Tier 0
#### Test configuration

For each configuration option, we check if logcollector and agentd correctly
starts and that any api request to the Manager configuration returns the same options that the specified 
in `ossec.conf`
