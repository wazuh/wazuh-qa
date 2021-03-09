
# Wazuh_testing package

This package contains a set of utilities and dependencies imported by the tests in order to facilitate testing. Its
structure is as follows:

```bash

wazuh_testing
    ├── __init__.py
    ├── analysis.py
    ├── cluster.py
    ├── data
    │   ├── event_analysis_schema.json
    │   ├── mitre_event.json
    │   ├── state_integrity_analysis_schema.json
    │   ├── syscheck_event.json
    │   └── syscheck_event_windows.json
    ├── fim.py
    ├── gcloud.py
    ├── mitre.py
    ├── vulnerability_detector.py
    ├── wazuh_db.py
    ├── tools
    │   ├── __init__.py
    │   ├── configuration.py
    │   ├── file.py
    │   ├── monitoring.py
    │   ├── services.py
    │   ├── system.py
    │   └── time.py
    │   └── utils.py
    └── wazuh_db.py
```

#### Python modules

These are `analysis.py`, `fim.py`, `mitre.py`, `vulnerability_detector.py` and `wazuh_db.py`. They have very specific
tools needed for each capability.

#### data

Folder with all the json schemas. One capability could have more than one schema depending on the platform.

#### tools

Folder with all the general tools that could be used in every test. They are grouped by:

- **Init**: `__init__` file with the common information between all these modules (paths set in execution time).

- **Configuration**:  Functions to configure our environment (rewrite `ossec.conf`, load it, change metadata...)

- **File**: Functions to work with files.

- **Monitoring**: Everything related to monitoring a file.

- **Services**: From controlling Wazuh services, daemons and socket to common processes.

- **Time**: Classes and functions to 'travel in time' (needed for scheduled monitoring) and manage dates.

- **Utils**: General behaviour tools.


## __init__

::: deps.wazuh_testing.wazuh_testing.__init__


## API

::: deps.wazuh_testing.wazuh_testing.api

## FIM

::: deps.wazuh_testing.wazuh_testing.fim

## Cluster

::: deps.wazuh_testing.wazuh_testing.cluster

## GCloud

::: deps.wazuh_testing.wazuh_testing.gcloud

## Logtest

::: deps.wazuh_testing.wazuh_testing.logtest

## Mitre

::: deps.wazuh_testing.wazuh_testing.mitre

## Remote

::: deps.wazuh_testing.wazuh_testing.remote

## Vulnerability detector

::: deps.wazuh_testing.wazuh_testing.vulnerability_detector

## WazuhDB

::: deps.wazuh_testing.wazuh_testing.wazuh_db

## Analysis

::: deps.wazuh_testing.wazuh_testing.analysis