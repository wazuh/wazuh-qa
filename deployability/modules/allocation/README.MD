## Allocation Module

### User documentation 

The execution of the allocation is carried out through the Workflow library, or by executing them manually through commands.
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


If one wishes to execute the allocaation module without installing the workflow engine, they can proceed by using the launcher (module/allocation/main.py):

1. Execution

  While in wazuh-qa/deployability

  ```bash
  python3 modules/allocation/main.py --action '{{}}' --provider '{{ vagrant }}' --size '{{ large }}' --composite-name '{{ composite-name }}' --inventory-output '{{ inventory }}' --track-output '{{ track }}'

  ```

  Example:
  ```bash
  python3 modules/allocation/main.py --action create --provider vagrant --size large --composite-name linux-ubuntu-22.04-amd64 --inventory-output "/tmp/dtt1-poc/agent-linux-ubuntu-22.04-amd64/inventory.yaml" --track-output "/tmp/dtt1-poc/agent-linux-ubuntu-22.04-amd64/track.yaml"
  ```

---

### Technical documentation

The allocation module allows creating infrastructure on both AWS and locally (using Vagrant).

Instructions can be initiated from the fixture and executed through the Workflow Engine or executed using Python commands.

In either case, the following information will be needed:

```yaml
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
```

In the provided fixture fragment, it is evident that to execute the Allocation module launcher (`allocation/main.py`), the action, provider, size, composite-name, inventory-output, and track-output must be specified.

For manual execution, an example command would be:

```bash
python3 modules/allocation/main.py --action create --provider vagrant --size large --composite-name linux-ubuntu-22.04-amd64 --inventory-output "/tmp/dtt1-poc/agent-linux-ubuntu-22.04-amd64/inventory.yaml" --track-output "/tmp/dtt1-poc/agent-linux-ubuntu-22.04-amd64/track.yaml"
```

The module is comprised of:

General-specific functions:

- **Launcher** (`/wazuh-qa/deployability/modules/allocation/main.py`): The entry point for the workflow or the user who wishes to execute a test.

- **Module functions** (`/wazuh-qa/deployability/modules/allocation/allocation.py`): Module-specific functions responsible for triggering the allocation.

- **Static functions** (`/wazuh-qa/deployability/modules/allocation/static`): Templates and static information for infrastructure creation.

Provider-specific functions:

- **AWS functions** (`/wazuh-qa/deployability/modules/allocation/aws`): Module-specific functions responsible for triggering the allocation.

- **Vagrant functions** (`/wazuh-qa/deployability/modules/allocation/vagrant`): Module-specific functions responsible for triggering the allocation.

- **Generic functions** (`/wazuh-qa/deployability/modules/allocation/generic`): Module-specific functions responsible for triggering the allocation.

Each provider will contain:

- **Modeler** (`/wazuh-qa/deployability/modules/allocation/{provider}/models.py`)
- **Credentials** (`/wazuh-qa/deployability/modules/allocation/{provider}/credentials.py`)
- **Provider** (`/wazuh-qa/deployability/modules/allocation/{provider}/provider.py`)
- **Information regarding the instance** (`/wazuh-qa/deployability/modules/allocation/{provider}/instance.py`)

![image](https://github.com/wazuh/wazuh-qa/assets/125690423/b79e2561-e675-4608-823d-ebc87de0555f)


[Allocation.drawio.zip](https://github.com/wazuh/wazuh-qa/files/14480890/Allocation.drawio.zip)

 
### License


WAZUH Copyright (C) 2015 Wazuh Inc. (License GPLv2)