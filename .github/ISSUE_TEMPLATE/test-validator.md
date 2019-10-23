---
name: 'Test: Validator'
about: Test suite for Validator.
title: ''
labels: ''
assignees: ''

---

# Validator

| Version | Revision | Branch |
| --- | --- | --- |
| x.y.z | rev | branch |

The validator CLI will have the following format: `check_configuration -t [config_file] -f [filepath]`.

`config_file`: `manager` for the manager configuration, `agent` for the agent configuration or `remote` for the centralized configuration (agent.conf).

`filepath`: This option indicate the path to the file to validate. By default the path is `/var/ossec/etc/ossec.conf` to `manager` and `agent`. The default of `remote` is `/var/ossec/etc/shared/default/agent.conf`.

While the module of the validator will have the following input format:
```JSON
{
  "operation": "GET",
  "type": "request",
  "version": "3.10",
  "component": "check_configuration",
  "data":
    {
      "type": "manager",
      "file": "/var/ossec/etc/ossec.conf"
    },
}

```
the fields `data.type` and `data.file` are the same as the fields commented above, in the CLI. The ouput expected will be the next:
```JSON
  "error": "0",
  "data": [
    {
      "type": "WARNING",
      "message": "The 'vulnerability-detector' module only works for the manager"
    },
    {
      "type": "INFO",
      "message": "WPK verification with CA is disabled"
    }
  ]
}

```

To check in every test:

- ossec.log don't show any information about the validator.
- Check the module and the CLI.
- Check with and without the -t option.

## Successful validation

- [ ] Successful validation of the manager confguration
- [ ] Successful validation of the agent configuration
- [ ] Successful validation of the remote configuration

## Manager

Unsucessful validation with an error in:

- [ ] Authd
- [ ] SCA
- [ ] FluentForwarder
- [ ] Remoted
- [ ] Active response
- [ ] Global
- [ ] Cluster 
- [ ] Syscheck
- [ ] Rootcheck
- [ ] Maild
- [ ] Agentless
- [ ] Wmodules
    - [ ] Osquery
    - [ ] Oscap
    - [ ] Syscollector
    - [ ] Ciscat
    - [ ] AWS
    - [ ] Vuldetector
    - [ ] Azure
    - [ ] Key resquest

## Agent

Unsucessful validation with an error in:

- [ ] Rootcheck
- [ ] Syscheck
- [ ] Localfile
- [ ] Labels
- [ ] Active response
- [ ] Client
- [ ] Wmodules
    - [ ] Osquery
    - [ ] Oscap
    - [ ] Syscollector
    - [ ] Ciscat
    - [ ] AWS
    - [ ] Vuldetector
    - [ ] Azure
    - [ ] Key resquest

## Remote

Unsucessful validation with an error in:

- [ ] Syscheck
- [ ] Rootcheck
- [ ] Localfile
- [ ] Labels
- [ ] Client
- [ ] Wmodules
    - [ ] Osquery
    - [ ] Oscap
    - [ ] Syscollector
    - [ ] Ciscat
    - [ ] AWS
    - [ ] Vuldetector
    - [ ] Azure
    - [ ] Key resquest