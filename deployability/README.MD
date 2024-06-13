## Deployability general documentation

### User documentation

To perform Deployability type tests, it is necessary to:

- Install Python libraries

For this purpose, it is recommended to use virtual environments. Follow the technical [documentation](https://docs.python.org/es/3/library/venv.html):

1. Activate the environment:

```
source {venv directory}/bin/activate
```

2. Clone the wazuh-qa repository:

Navigate to the project directory and switch to the project branch:

```
git clone https://github.com/wazuh/wazuh-qa.git
```

Navigate to the project directory and switch to the project branch:

```
cd wazuh-qa
git checkout {project-branch}
```

3. Install requirements:

```
pip3 install -r deployability/deps/requirements.txt
```

4. Install the JobFlow engine library and its launcher:

While in wazuh-qa:

```
cd modules
pip3 uninstall -y jobflow && pip3 install .
```

5. Test Fixture to Execute

It will be necessary to create a fixture (yaml file) where the infrastructure, provisioning, and tests to be executed will be declared.

> Note:  It is possible to find some fixture examples in deployability/modules/jobflow/examples/


Example:

```
version: 0.1
description: This YAML is used to test agents' deployment for DDT1 PoC
variables:
  agents-os:
    - linux-ubuntu-22.04-amd64
  manager-os: linux-ubuntu-22.04-amd64
  infra-provider: vagrant
  working-dir: /tmp/dtt1-poc

tasks:
  # Generic agent test task
  - task: "run-agent-tests-{agent}"
    description: "Run tests uninstall for the {agent} agent."
    do:
      this: process
      with:
        path: python3
        args:
          - modules/testing/main.py
          - inventory: "{working-dir}/agent-{agent}/inventory.yaml"
          - dependencies:
            - manager: "{working-dir}/manager-{manager-os}/inventory.yaml"
            - agent: "{working-dir}/agent-{agent}/inventory.yaml"
          - tests: "install,register,stop"
          - component: "agent"
          - wazuh-version: "4.7.1"
          - wazuh-revision: "40709"
    depends-on:
      - "provision-install-{agent}"
      - "provision-manager"
    foreach:
      - variable: agents-os
        as: agent

  # Generic agent test task
  - task: "run-agent-tests-uninstall-{agent}"
    description: "Run tests uninstall for the {agent} agent."
    do:
      this: process
      with:
        path: python3
        args:
          - modules/testing/main.py
          - inventory: "{working-dir}/agent-{agent}/inventory.yaml"
          - dependencies:
            - manager: "{working-dir}/manager-{manager-os}/inventory.yaml"
          - tests: "uninstall"
          - component: "agent"
          - wazuh-version: "4.7.1"
          - wazuh-revision: "40709"
    depends-on:
      - "run-agent-tests-{agent}"
      - "provision-uninstall-{agent}"
    foreach:
      - variable: agents-os
        as: agent

  # Unique manager provision task
  - task: "provision-manager"
    description: "Provision the manager."
    do:
      this: process
      with:
        path: python3
        args:
          - modules/provision/main.py
          - inventory-manager: "{working-dir}/manager-{manager-os}/inventory.yaml"
          - install:
            - component: wazuh-manager
              type: package
    depends-on:
      - "allocate-manager"

  # Unique manager allocate task
  - task: "allocate-manager"
    description: "Allocate resources for the manager."
    do:
      this: process
      with:
        path: python3
        args:
          - modules/allocation/main.py
          - action: create
          - provider: "{infra-provider}"
          - size: large
          - composite-name: "{manager-os}"
          - inventory-output: "{working-dir}/manager-{manager-os}/inventory.yaml"
          - track-output: "{working-dir}/manager-{manager-os}/track.yaml"
    cleanup:
      this: process
      with:
        path: python3
        args:
          - modules/allocation/main.py
          - action: delete
          - track-output: "{working-dir}/manager-{manager-os}/track.yaml"

  # Generic agent provision task
  - task: "provision-install-{agent}"
    description: "Provision resources for the {agent} agent."
    do:
      this: process
      with:
        path: python3
        args:
          - modules/provision/main.py
          - inventory-agent: "{working-dir}/agent-{agent}/inventory.yaml"
          - inventory-manager: "{working-dir}/manager-{manager-os}/inventory.yaml"
          - install:
            - component: wazuh-agent
              type: package
            - component: curl
    depends-on:
      - "allocate-{agent}"
      - "provision-manager"
    foreach:
      - variable: agents-os
        as: agent

  # Generic agent provision task
  - task: "provision-uninstall-{agent}"
    description: "Provision resources for the {agent} agent."
    do:
      this: process
      with:
        path: python3
        args:
          - modules/provision/main.py
          - inventory-agent: "{working-dir}/agent-{agent}/inventory.yaml"
          - inventory-manager: "{working-dir}/manager-{manager-os}/inventory.yaml"
          - uninstall:
            - component: wazuh-agent
              type: package
    depends-on:
      - "provision-install-{agent}"
    foreach:
      - variable: agents-os
        as: agent

  # Generic agent allocate task
  - task: "allocate-{agent}"
    description: "Allocate resources for the {agent} agent."
    do:
      this: process
      with:
        path: python3
        args:
          - modules/allocation/main.py
          - action: create
          - provider: "{infra-provider}"
          - size: small
          - composite-name: "{agent}"
          - inventory-output: "{working-dir}/agent-{agent}/inventory.yaml"
          - track-output: "{working-dir}/agent-{agent}/track.yaml"
    cleanup:
      this: process
      with:
        path: python3
        args:
          - modules/allocation/main.py
          - action: delete
          - track-output: "{working-dir}/agent-{agent}/track.yaml"
    foreach:
      - variable: agents-os
        as: agent
```

Following the schema of the example:

Configure the following parameters depending on your test case:

```
variables/agent-os
variables/manager-os
infra-provider
working-dir
tasks
```

Pay attention to the tasks:

```
args
depends-on
```

> Note: In args, configure the launcher's path correctly (main.py files in each module), and to fill depends-on, consider the steps of your test (allocation, provision, and test)

6. Execution of Command (local):

Execute the command by referencing the parameters required by the library (launcher).

```
python3 -m jobflow {.yaml fixture path}
```

Example

```
python3 -m jobflow modules/jobflow/examples/dtt1-agents-poc.yaml
```


---

### Technical documentation

- Modules

The framework has 4 modules (`allocation`, `provision`, `testing`, `observability`) that must act consecutively, and a 5th module that orchestrates the previous modules (`Jobflow`).

|Module|Description
|--|--|
|JobFlow (Orchestrator)|Receives a YAML containing all the instructions to execute for the test development. It contains instructions for allocation, provision, and testing.
|Allocation| Receives instructions for the desired architecture and creates the structures, generating IPs, and ports either in AWS or locally with Vagrant.
|Provision| Installs applications on the structures created in allocation.
|Testing| Executes tests on the previously defined structures and triggers actions depending on the test.
|Observability| Allows the ordered and indexed visualization of data obtained in the 3 previous modules.

- Directory Structure

```
wazuh-qa/
└── deployability
    ├── deps
    ├── Jenkinsfiles
    ├── modules
    │   ├── allocation
    │   ├── generic
    │   ├── provision
    │   ├── testing
    │   └── jobflow
    └── plugins
```
Deployability contains the following directories:

|Directory|Description|
|---|---|
|deps|Contains information about the dependencies used for installing the necessary libraries for running the framework.|
|Jenkinsfiles|Contains instructions for the pipelines for test execution.|
|modules|Contains files, the launcher (main.py), and playbooks.|
|plugins|Contains modules for the observability plugin.|

#### Overview

![image](https://github.com/wazuh/wazuh-qa/assets/2949519/29b600cf-44bd-412c-b02f-9b08353babde)

#### Allocator, provision & test process

![image](https://github.com/wazuh/wazuh-qa/assets/2949519/9338ccc4-2ffa-47d4-b4cc-86c2a8aa5851)



----


[draw-plot.zip](https://github.com/user-attachments/files/15792115/draw-plot.zip)



### License

WAZUH Copyright (C) 2015 Wazuh Inc.  (License GPLv2)
