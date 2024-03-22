# wazuh-qa

Wazuh - System quality assurance automation templates

## Setting up a test environment

To run these tests a **Linux** machine will be required.

In the event that the tests are to be executed using AWS EC2 instances:

### EC2 requirements for system testing

| Environment                  | EC2                                       |
|------------------------------|-------------------------------------------|
|Basic_cluster                 |Ubuntu 22.04.2 LTS C5.XLarge 15GB SSD      |
|Big_cluster_40_agents         |Ubuntu 22.04.2 LTS T3.Large 60GB SSD       |
|Agentless_cluster             |Ubuntu 22.04.2 LTS C5a.XLarge 30GB SSD       |
|Four_manager_disconnected_node|Ubuntu 22.04.2 LTS T3.Large 30GB SSD       |
|One_manager_agent             |Ubuntu 22.04.2 LTS T3.Large 30GB SSD       |
|Manager_agent                 |Ubuntu 22.04.2 LTS T3.Large 30GB SSD       |
|Enrollment_cluster            |Ubuntu 22.04.2 LTS T3.Large 30GB SSD       |
|Basic_environment             |Ubuntu 22.04.2 LTS T3.Large 30GB SSD       |


Now, the following tools will need to be installed:

- [Docker](https://docs.docker.com/install/)
- [Ansible](https://docs.ansible.com/ansible/latest/installation_guide/intro_installation.html)

### Dependencies

In addition, we need the Wazuh-testing package. So first, we need to install all these Python dependencies, we can use
this command:

```shell script
pip3 install -r requirements.txt
```

_**NOTE:** `jq` library can only be installed with `pip` on **Linux**_

### Wazuh-Testing package

We have a Python package at `wazuh-qa/deps/` with all the tools needed to run these tests. From file monitoring classes
to callbacks or functions to create the test environment. Without installing this package, we cannot run these tests. It
has the following structure:

```bash
wazuh_testing
    ├── setup.py
    └── wazuh_testing
        ├── __init__.py
        ├── analysis.py
        ├── data
        │   ├── event_analysis_schema.json
        │   ├── mitre_event.json
        │   ├── state_integrity_analysis_schema.json
        │   ├── syscheck_event.json
        │   └── syscheck_event_windows.json
        ├── fim.py
        ├── mitre.py
        ├── tools
        │   ├── __init__.py
        │   ├── configuration.py
        │   ├── file.py
        │   ├── monitoring.py
        │   ├── services.py
        │   ├── system.py
        │   └── time.py
        └── wazuh_db.py
```

#### setup.py

Python module with the needed code to install this package into our Python interpreter.

#### wazuh_testing

##### Python modules

These are _analysis.py_, _fim.py_, _mitre.py_ and _wazuh_db.py_. They have very specific tools needed for each
capability.

##### data

Folder with all the json schemas. One capability could have more than one schema depending on the platform.

##### tools

Folder with all the general tools that could be used in every test. They are grouped by:

- **Init**: `__init__` file with the common information between all these modules (paths set in execution time).

- **Configuration**:  functions to configure our environment (rewrite `ossec.conf`, load it, change metadata...)

- **File**: functions to work with files.

- **Monitoring**: everything related to monitoring a file.

- **Services**: from controlling Wazuh services, daemons and socket to common processes.

- **System**: functions that allow us to perform operations on our system's hosts

- **Time**:  classes and functions to 'travel in time' (needed for scheduled monitoring) and manage dates.

To install it:

```shell script
cd wazuh-qa/deps/wazuh_testing
pip3 install .Description
```

_**NOTE:** It is important to reinstall this package every time we modify anything
from `wazuh-qa/packages/wazuh_testing`_

```shell script
cd wazuh-qa/deps/wazuh_testing
pip3 uninstall -y wazuh_testing && pip3 install .
```

## System tests

**DISCLAIMER:** this guide assumes you have a proper testing environment. If you do not, please check
our [testing environment guide](#setting-up-a-test-environment).

Our cluster system tests are located in `wazuh-qa/tests/system/`. They are organized by functionalities and each one may
required an specific testing environment located in `wazuh-qa/tests/system/provisioning`:

| Functionality                                                             | Required environment           |
|---------------------------------------------------------------------------|--------------------------------|
| test_cluster/test_agent_enrollment                                        | enrollment_cluster             |
| test_agent_auth/test_agent_auth                                           | basic_environment              |
| test_enrollment/test_enrollment                                           | basic_environment              |
| test_files_cud/test_files_cud                                             | one_manager_agent              |
| test_cluster/test_agent_info_sync                                         | basic_cluster                  |
| test_cluster/test_agent_key_polling                                       | basic_cluster                  |
| test_cluster/test_agent_files_deletion                                    | basic_cluster                  |
| test_cluster/test_integrity_sync                                          | agentless_cluster              |
| test_cluster/test_ruleset_sync_status                                     | agentless_cluster              |
| test_jwt_invalidation                                                     | agentless_cluster              |
| test_active_response_log_format                                           | manager_agent                  |
| test_fim/test_synchronization                                             | one_manager_agent              |
| test_cluster/test_correct_merged_file_generation                          | one_manager_agent              |
| test_multigroups/test_multigroups                                         | basic_cluster                  |
| test_cluster/test_agent_groups/test_agent_groups_forced_change            | basic_cluster                  |
| test_cluster/test_agent_groups/test_agent_default_group_added             | enrollment_cluster             |
| test_cluster/test_agent_groups/test_agent_groups_new_cluster_node         | four_manager_disconnected_node |
| test_cluster/test_agent_groups/test_agent_groups                          | enrollment_cluster             |
| test_cluster/test_agent_groups/test_assign_agent_group_with_enrollment    | enrollment_cluster             |
| test_cluster/test_agent_groups/test_assign_agent_never_connected_to_group | enrollment_cluster             |
| test_cluster/test_agent_groups/test_assign_agent_to_a_group_api           | enrollment_cluster             |
| test_cluster/test_agent_groups/test_assign_agent_to_a_group_by_tool       | enrollment_cluster             |
| test_cluster/test_agent_groups/test_assign_agent_to_a_group               | enrollment_cluster             |
| test_cluster/test_agent_groups/test_assign_groups_guess                   | enrollment_cluster             |
| test_cluster/test_agent_groups/test_group_hash                            | enrollment_cluster             |
| test_cluster/test_agent_groups/test_groups_sync_default                   | big_cluster_40_agents          |
| test_cluster/test_agent_groups/test_groups_sync_time                      | big_cluster_40_agents          |
| test_shutdown_message/test_shutdown_message                               | big_cluster_40_agents          |

### Test structure

Every group will have the following structure:

```bash
<functionality>
├── conftest.py
├── data
│   ├── config.yml
│   └── messages.yml
├── files
├── test_<functionality>.py
└── tmp
```

#### conftest

Our conftests file will give us the path to the inventory file so that we can run the different instances of our system
tests.

#### data

Folder which includes the configuration that will be applied to our environment. It also contains a file where you
specify which messages are expected in each of the nodes.

##### messages.yml

```yaml
---
# sample messages
node_name:
  - regex: ".*wazuh-master restarted.*"
    path: "/var/ossec/logs/ossec.log"
    timeout: 60
```

- **node_name**: Name of the node where we are going to look for the message that matches with the regex.
- **regex**: Regular expression we will look for in the file.
- **path**: Path to the file to be checked.
- **timeout**: Deadline for message to be shown.

##### config.yml

```yaml
---
# sample configuration
node_name:
  - description: Enable remoted agent_key_polling at master side
    after: <remote>
    before: </remote>
    content: |
      <connection>secure</connection>
      <port>1514</port>
      <protocol>tcp</protocol>
      <queue_size>131072</queue_size>
      <key_polling enabled="yes">
        <mode>local</mode>
      </key_polling>
```

- **node_name**: Name of the node where we are going to look for the message.
- **description**: Short description of the configuration to be modified.
- **after**: The new configuration will be inserted after what is specified here.
- **before**: The new configuration will be inserted before what is specified here.
- **content**: New configuration lines.

### Pytest

First, we need to start our Ansible environment. To do this, we must execute this command
in `system/provisioning/<specified_cluster_environment>` path:

```shell script
ansible-playbook -i inventory.yml playbook.yml
```

You can specify a package as `package_repository`, `repository`, `package_version`, `package_revision` parameters:
```shell script
ansible-playbook -i inventory.yml playbook.yml --extra-vars='{"package_repository":"packages", "repository": "4.x", "package_version": "4.4.0", "package_revision": "1"}'
```

In the basic cluster, you also have to specify a branch from the Wazuh QA repository.

```shell script
ansible-playbook -i inventory.yml playbook.yml --extra-vars='{"package_repository":"packages", "repository": "4.x", "package_version": "4.4.0", "package_revision": "1", "wazuh_qa_branch":"v4.3.0-rc1"}'
```

We use [pytest](https://docs.pytest.org/en/latest/contents.html) to run our cluster system tests. Pytest will
recursively look for the closest `conftest` to import all the variables and fixtures needed for every test. If something
is lacking from the closest one, it will look for the next one (if possible) until reaching the current directory. This
means we need to run every test from the following path, where the general _conftest_ for cluster system tests is:

```shell script
cd wazuh-qa/tests/system/cluster
```

To run any test, we just need to call `pytest` from `python3` using the following line:

```shell script
python3 -m pytest [options] [file_or_dir] [file_or_dir] [...]
```

If we want to launch all the tests in the same environment, without having to launch several executions depending on the directory, we can launch it with the `-m` option:

```shell script
python3 -m pytest -m [environment]_env [file_or_dir] [file_or_dir] [...]
```

For example, for the `basic_cluster` environment tests:

```shell script
python3 -m pytest tests/system -m basic_cluster_env
```

**Options:**

- `v`: verbosity level (-v or -vv. Highly recommended to use -vv when tests are failing)
- `s`: shortcut for --capture=no. This will show the output in real time
- `x`: instantly exit after the first error. Very helpful when using a log truncate since it will keep the last failed
  result
- `m`: only run tests matching given expression (-m MARKEXPR)
- `--tier`: only run tests with given tier (ex. --tier 2)
- `--html`: generates a HTML report for the test results. (ex. --html=report.html)
- `--default-timeout`: overwrites the default timeout (in seconds). This value is used to make a test fail if a
  condition is not met before the given time lapse. Some tests make use of this value and other has other fixed timeout
  that cannot be modified.

_Use `-h` to see the rest or check its [documentation](https://docs.pytest.org/en/latest/usage.html)._

#### Cluster system tests example

##### Ansible environment setup

```shell script
ansible-playbook -i inventory.yml playbook.yml

PLAY [Create our container (Master)] ********************************************************************************************************************************************************************************************

TASK [Gathering Facts] **********************************************************************************************************************************************************************************************************
ok: [localhost]

TASK [Create a network] *********************************************************************************************************************************************************************************************************
changed: [localhost]

TASK [docker_container] *********************************************************************************************************************************************************************************************************
changed: [localhost]

PLAY [Create our container (Worker1)] *******************************************************************************************************************************************************************************************

TASK [Gathering Facts] **********************************************************************************************************************************************************************************************************
ok: [localhost]

TASK [docker_container] *********************************************************************************************************************************************************************************************************
changed: [localhost]

PLAY [Create our container (Worker2)] *******************************************************************************************************************************************************************************************

TASK [Gathering Facts] **********************************************************************************************************************************************************************************************************
ok: [localhost]

TASK [docker_container] *********************************************************************************************************************************************************************************************************
changed: [localhost]

PLAY [Create our container (Agent1)] ********************************************************************************************************************************************************************************************

TASK [Gathering Facts] **********************************************************************************************************************************************************************************************************
ok: [localhost]

TASK [docker_container] *********************************************************************************************************************************************************************************************************
changed: [localhost]

PLAY [Create our container (Agent2)] ********************************************************************************************************************************************************************************************

TASK [Gathering Facts] **********************************************************************************************************************************************************************************************************
ok: [localhost]

TASK [docker_container] *********************************************************************************************************************************************************************************************************
changed: [localhost]

PLAY [Create our container (Agent3)] ********************************************************************************************************************************************************************************************

TASK [Gathering Facts] **********************************************************************************************************************************************************************************************************
ok: [localhost]

TASK [docker_container] *********************************************************************************************************************************************************************************************************
changed: [localhost]

PLAY [Wazuh Master] *************************************************************************************************************************************************************************************************************

TASK [Gathering Facts] **********************************************************************************************************************************************************************************************************
ok: [wazuh-master]

TASK [roles/master-role : Installing dependencies using apt] ********************************************************************************************************************************************************************
changed: [wazuh-master]

TASK [roles/master-role : Clone wazuh repository] *******************************************************************************************************************************************************************************
changed: [wazuh-master]

...

PLAY RECAP **********************************************************************************************************************************************************************************************************************
localhost                  : ok=13   changed=7    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
wazuh-agent1               : ok=9    changed=8    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
wazuh-agent2               : ok=9    changed=8    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
wazuh-agent3               : ok=9    changed=8    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
wazuh-master               : ok=11   changed=10   unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
wazuh-worker1              : ok=9    changed=8    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
wazuh-worker2              : ok=9    changed=8    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0


```

##### Test results

```shell script
python3 -m pytest -vvsx test_agent_key_polling/test_agent_key_polling.py
=========================================================================== test session starts ===========================================================================
platform linux -- Python 3.7.5, pytest-4.5.0, py-1.8.1, pluggy-0.13.1 -- /usr/bin/python3
cachedir: .pytest_cache
metadata: {'Python': '3.7.5', 'Platform': 'Linux-5.3.0-7642-generic-x86_64-with-Ubuntu-19.10-eoan', 'Packages': {'pytest': '4.5.0', 'py': '1.8.1', 'pluggy': '0.13.1'}, 'Plugins': {'html': '2.0.1', 'tavern': '0.34.0', 'testinfra': '5.0.0', 'metadata': '1.8.0'}}
rootdir: /home/adriiiprodri/Desktop/git/wazuh-qa/tests/system/cluster
plugins: html-2.0.1, tavern-0.34.0, testinfra-5.0.0, metadata-1.8.0
collected 1 item

test_agent_key_polling/test_agent_key_polling.py::test_agent_key_polling 2020-03-31 09:42:46,087 - wazuh_testing - DEBUG - Add new file composer process for wazuh-master and path: /var/ossec/logs/ossec.log
2020-03-31 09:42:46,089 - wazuh_testing - DEBUG - Add new file monitor process for wazuh-master and path: /var/ossec/logs/ossec.log
2020-03-31 09:42:46,089 - wazuh_testing - DEBUG - Starting file composer for wazuh-master and path: /var/ossec/logs/ossec.log. Composite file in /home/adriiiprodri/Desktop/git/wazuh-qa/tests/system/cluster/test_agent_key_polling/tmp/wazuh-master_ossec.log.tmp
2020-03-31 09:42:46,091 - wazuh_testing - DEBUG - Add new file composer process for wazuh-worker1 and path: /var/ossec/logs/ossec.log
2020-03-31 09:42:46,092 - wazuh_testing - DEBUG - Starting QueueMonitor for wazuh-master and message: .*Agent key generated for agent 'wazuh-agent2'.*
2020-03-31 09:42:46,092 - wazuh_testing - DEBUG - Add new file monitor process for wazuh-worker1 and path: /var/ossec/logs/ossec.log
2020-03-31 09:42:46,093 - wazuh_testing - DEBUG - Starting file composer for wazuh-worker1 and path: /var/ossec/logs/ossec.log. Composite file in /home/adriiiprodri/Desktop/git/wazuh-qa/tests/system/cluster/test_agent_key_polling/tmp/wazuh-worker1_ossec.log.tmp
2020-03-31 09:42:46,094 - wazuh_testing - DEBUG - Add new file composer process for wazuh-agent2 and path: /var/ossec/logs/ossec.log
2020-03-31 09:42:46,095 - wazuh_testing - DEBUG - Starting QueueMonitor for wazuh-worker1 and message: .*Authentication error. Wrong key or corrupt payload. Message received from agent '002'.*
2020-03-31 09:42:46,096 - wazuh_testing - DEBUG - Add new file monitor process for wazuh-agent2 and path: /var/ossec/logs/ossec.log
2020-03-31 09:42:46,097 - wazuh_testing - DEBUG - Starting file composer for wazuh-agent2 and path: /var/ossec/logs/ossec.log. Composite file in /home/adriiiprodri/Desktop/git/wazuh-qa/tests/system/cluster/test_agent_key_polling/tmp/wazuh-agent2_ossec.log.tmp
2020-03-31 09:42:46,099 - wazuh_testing - DEBUG - Starting QueueMonitor for wazuh-agent2 and message: .*Lost connection with manager. Setting lock.*
2020-03-31 09:42:49,100 - wazuh_testing - DEBUG - Finishing QueueMonitor for wazuh-master and message: .*Agent key generated for agent 'wazuh-agent2'.*
2020-03-31 09:42:49,101 - wazuh_testing - DEBUG - Finishing QueueMonitor for wazuh-worker1 and message: .*Authentication error. Wrong key or corrupt payload. Message received from agent '002'.*
2020-03-31 09:42:49,106 - wazuh_testing - DEBUG - Finishing QueueMonitor for wazuh-agent2 and message: .*Lost connection with manager. Setting lock.*
2020-03-31 09:42:49,107 - wazuh_testing - DEBUG - Starting QueueMonitor for wazuh-agent2 and message: .*Trying to connect to server \(wazuh-worker1.*
2020-03-31 09:42:57,113 - wazuh_testing - DEBUG - Finishing QueueMonitor for wazuh-agent2 and message: .*Trying to connect to server \(wazuh-worker1.*
2020-03-31 09:42:57,113 - wazuh_testing - DEBUG - Starting QueueMonitor for wazuh-agent2 and message: .*Connected to the server \(wazuh-worker1.*
2020-03-31 09:42:57,113 - wazuh_testing - DEBUG - Finishing QueueMonitor for wazuh-agent2 and message: .*Connected to the server \(wazuh-worker1.*
2020-03-31 09:42:58,117 - wazuh_testing - DEBUG - Cleaning temporal files...
2020-03-31 09:42:58,118 - wazuh_testing - DEBUG - Checking results...
2020-03-31 09:42:58,123 - wazuh_testing - DEBUG - Received from wazuh-master the expected message: 2020/03/31 09:42:47 wazuh-authd: INFO: Agent key generated for agent 'wazuh-agent2' (requested locally)
2020-03-31 09:42:58,124 - wazuh_testing - DEBUG - Received from wazuh-worker1 the expected message: 2020/03/31 09:42:47 wazuh-remoted: WARNING: (1404): Authentication error. Wrong key or corrupt payload. Message received from agent '002' at 'any'.
2020-03-31 09:42:58,125 - wazuh_testing - DEBUG - Received from wazuh-agent2 the expected message: 2020/03/31 09:42:47 wazuh-agentd: ERROR: (1137): Lost connection with manager. Setting lock.
2020-03-31 09:42:58,125 - wazuh_testing - DEBUG - Received from wazuh-agent2 the expected message: 2020/03/31 09:42:56 wazuh-agentd: INFO: Trying to connect to server (wazuh-worker1/172.18.0.3:1514/tcp).
2020-03-31 09:42:58,126 - wazuh_testing - DEBUG - Received from wazuh-agent2 the expected message: 2020/03/31 09:42:56 wazuh-agentd: INFO: (4102): Connected to the server (wazuh-worker1/172.18.0.3:1514/tcp).
PASSED

======================================================================== 1 passed in 81.86 seconds ========================================================================

```
