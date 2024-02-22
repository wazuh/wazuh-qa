## Testing Module

### User documentation

The execution of the tests is carried out through the Workflow library, or by executing them manually through commands.
Execution can be done from any operating system.

Initially, Python libraries must be installed. It is recommended to use virtual environments. Follow the technical documentation at https://docs.python.org/3/library/venv.html.

1. Activate the environment:

  ```bash
  source {venv directory}/bin/activate
  ```

2. Clone the `wazuh-qa` repository:

  Navigate to the project directory and switch to the project branch:

  ```bash
  cd wazuh-qa
  git checkout {project-branch}
  ```
> Note: temporary dev project-branch is `enhancement/4495-DTT1`

3. Install requirements:

  ```bash
  pip3 install -r deployability/deps/requirements.txt
  ```

Now, it is possible to use worklow engine library to launch provision module doing the following steps:

1. Install the Workflow engine library and its launcher:

  While in wazuh-qa:

  ```bash
  cd modules
  pip3 uninstall -y workflow_engine && pip3 install .
  ```

2. Test Fixture to Execute:

      It will be necessary to create a fixture (yaml file) where the infrastructure, provisioning, and tests to be executed will be declared.

      >Note: It is possible to find some fixture examples in deployability/modules/workflow_engine/examples/ 

      Example:
      
      ```bash
      version: 0.1
      description: This workflow is used to test agents deployment por DDT1 PoC
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

      ```yaml
      variables/agent-os
      variables/manager-os
      infra-provider
      working-dir
      tasks
      ```

      Pay attention to the tasks:

      ```yaml
      args
      depends-on
      ```

      >Note: In args, configure the launcher's path correctly (main.py files in each module), and to fill `depends-on`, consider the steps of your test (allocation, provision, and test) 

3. Execution of Command (local):

  Execute the command by referencing the parameters required by the library (launcher).
  
  ```bash
  python3 -m workflow_engine {.yaml fixture path} 
  ```

  Example

  ```bash
  python3 -m workflow_engine modules/workflow_engine/examples/dtt1-agents-poc.yaml
  ```

  > Note The command execution can also be mediated through Jenkins.


If one wishes to execute the testing module without installing the workflow engine, they can proceed by using the launcher (module/testing/main.py):

1. Execution

  While in wazuh-qa/deployability

  ```bash
  python3 modules/testing/main.py --inventory '{{ inventory }}' --component {{ component }} --wazuh-version '{{ wazuh_version }}' --wazuh-revision '{{ wazuh_revision }}' --tests install --dependencies '{{ dependencies }}' --live {{ live }}

  ```

  Example:
  ```bash
  python3 modules/testing/main.py --inventory "/tmp/dtt1-poc/agent-linux-ubuntu-22.04-amd64/inventory.yaml" --component "agent" --wazuh-version "4.7.2" --wazuh-revision "1" --tests install --dependencies '{"manager":"/tmp/dtt1-poc/manager-linux-ubuntu-22.04-amd64/inventory.yaml"}' --live False
  ```

---

### Technical documentation

The testing module allows the execution of tests on agents and central components.

Instructions can be received from the fixture and executed through the Workflow Engine or run through commands on an already provisioned infrastructure.

In both cases, the following information will be required:

```yaml
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
        - tests: "install,basic_info,connection,register,repo,restart,stop,uninstall"
        - component: "agent"
        - wazuh-version: "4.7.2"
        - wazuh-revision: "1"
        - live: False
```

In the exposed fixture fragment, it can be observed that for the execution of the testing module launcher (`testing/main.py`), it is necessary to provide the inventory, dependencies, component, tests to execute, Wazuh version, Wazuh revision, and whether the repository is live or not (if not, it will look for information in `packages-dev` pre-release).

For manual execution, an example command would be:

```bash
python3 modules/testing/main.py --inventory "/tmp/dtt1-poc/agent-linux-ubuntu-22.04-amd64/inventory.yaml" --component "agent" --wazuh-version "4.7.2" --wazuh-revision "1" --tests install --dependencies '{"manager":"/tmp/dtt1-poc/manager-linux-ubuntu-22.04-amd64/inventory.yaml"}' --live False
```

The module is composed of:

- **Launcher** (`/wazuh-qa/deployability/modules/testing/main.py`): Entry point for the workflow or the user who wishes to execute a test.
  
- **Parameter validator** (`/wazuh-qa/deployability/modules/testing/models.py`): Validator for parameters entered by the Workflow or the user.
  
- **Module functions** (`/wazuh-qa/deployability/modules/testing/testing.py`): Module-specific functions responsible for triggering the test.
  
- **Executor** (`/wazuh-qa/deployability/modules/provision/actions.py`): Executes the provision using Actions in the generic module.
  
- **Playbooks** (`/wazuh-qa/deployability/modules/playbooks`): Contains setup, execution, and post-test cleanup playbooks.
  
- **Tests** (`/wazuh-qa/deployability/modules/tests`): Contains the test_agent and test_manager directories where the tests to be executed are located.
  
- **Helpers** (`/wazuh-qa/deployability/modules/tests/helpers`): Contains files that enable the execution of the test.
  
- **Conftest** (`/wazuh-qa/deployability/modules/tests/conftest.py`): Contains information that will be transferred from the parameter validator to the tests.


![image](https://github.com/wazuh/wazuh-qa/assets/125690423/58332378-489a-49da-a73a-4d87d6bed3bc)

[Testing.drawio.zip](https://github.com/wazuh/wazuh-qa/files/14372508/Testing.drawio.zip)

The testing module should receive the infrastructure generated and provisioned by the allocation and provision modules. The module has the ability to execute actions on the hosts as well as perform the necessary validation.

In the case of agent tests, the provisioning of the manager must be done by the provisioner. The install test will perform both installation and validation, so it should always be placed as the first test in the test list. The same situation will occur with the uninstall test, which will go to the end of the test list because it will execute the uninstallation prior to validation.

### License
WAZUH Copyright (C) 2015 Wazuh Inc. (License GPLv2)