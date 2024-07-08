## JobFlow engine

### User documentation

The execution of the JobFlow engine is done through the installation of its library.

Initially, Python libraries must be installed. It is recommended to use virtual environments. Follow the technical documentation at https://docs.python.org/3/library/venv.html.

To use this module, you should use a Debian-based system, we recommend using Ubuntu 22.04 for full compatibility, you must have installed at least Python 3.10.12 and pip3 22.0.2

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

3. Install requirements:

	```bash
	pip3 install -r deployability/deps/requirements.txt
	```

4. Install the JobFlow engine library and its launcher:

	While in wazuh-qa:

	```bash
	cd modules
	pip3 uninstall -y jobflow && pip3 install .
	```

5. Test Fixture to Execute:

      It will be necessary to create a fixture (YAML file) where the infrastructure, provisioning, and tests to be executed will be declared.

      >Note: It is possible to find some fixture examples in deployability/modules/jobflow/examples/

      Example:

      ```bash
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

7. Execution of Command (local):

	Execute the command by referencing the parameters required by the library (launcher).

	```bash
	python3 -m jobflow {.yaml fixture path}
	```

	Example

	```bash
	python3 -m jobflow modules/jobflow/examples/dtt1-agents-poc.yaml
	```

	> Note The command execution can also be mediated through Jenkins.

---

### Technical documentation

`JobFlow engine` is the orchestrator of the deployability test architecture.

Its function is to allow the ordered and structured execution in steps of allocation, provision, and testing.

`The JobFlow engine` receives instructions through a `YAML document`, the structure of which can be exemplified in tests found in:
`wazuh-qa/deployability/modules/jobflow/examples`

**In these tests**:
	- Tasks: define the steps.
	- Task: defines a step.

**Within Task**:
	- description: description of the task.
	- do: instructions for the task.
	- this: nature of the task.
	- with: tools with which the task will be executed.
	- path: executable.
	- args: arguments. it receives the binary or file to execute and the parameters.
	- depends-on: steps prior to the execution of that task.
	- foreach: loop that executes the task on the previously declared hosts.

```bash
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
```

These tasks are executed by the `JobFlow engine` launcher installed as jobflow library in your virtual environment.

This launcher receives the parameters, sets up the test logs, and proceeds with the ordered execution.

The parameters sent from the launcher are processed by deployability/modules/jobflow/models.py, which checks the nature of the parameters sent and filters out incorrect parameters.

![image](https://github.com/wazuh/wazuh-qa/assets/2949519/ee6231c2-9c97-4d9b-8c7d-af1cdce92d28)

These are then sent to `deployability/modules/jobflow/jobflow_processor.py`, where using `deployability/modules/schemas`, instructions in YAML are received and the schema of the instructions is checked.

The commands are executed in the JobFlowProcessor of the same file, which also handles parallel executions and aborts failed executions.

[WF.drawio.zip](https://github.com/user-attachments/files/15792275/WF.drawio.zip)


### License

WAZUH Copyright (C) 2015 Wazuh Inc.  (License GPLv2)
