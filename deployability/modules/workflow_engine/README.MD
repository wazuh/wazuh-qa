## Workflow engine
            
### User documentation     
   
The execution of the Workflow is done through the installation of its library.

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

3. Install requirements:

	```bash
	pip3 install -r deployability/deps/requirements.txt
	```

4. Install the Workflow engine library and its launcher:

	While in wazuh-qa:

	```bash
	cd modules
	pip3 uninstall -y workflow_engine && pip3 install .
	```

5. Test Fixture to Execute:

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

7. Execution of Command (local):

	Execute the command by referencing the parameters required by the library (launcher).
	
	```bash
	python3 -m workflow_engine {.yaml fixture path} 
	```

	Example

	```bash
	python3 -m workflow_engine modules/workflow_engine/examples/dtt1-agents-poc.yaml
	```

	> Note The command execution can also be mediated through Jenkins.

---

### Technical documentation

`Workflow Engine` is the orchestrator of the deployability test architecture.

Its function is to allow the ordered and structured execution in steps of allocation, provision, and testing.

`The Workflow Engine` receives instructions through a `YAML document`, the structure of which can be exemplified in tests found in:
`wazuh-qa/deployability/modules/workflow_engine/examples`

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

These tasks are executed by the `Workflow Engine` launcher installed as workflow_engine library in your virtual environment.

This launcher receives the parameters, sets up the test logs, and proceeds with the ordered execution.

The parameters sent from the launcher are processed by deployability/modules/workflow_engine/models.py, which checks the nature of the parameters sent and filters out incorrect parameters.

![image](https://github.com/wazuh/wazuh-qa/assets/125690423/32aa77b7-f294-41ac-af93-db8a084dbad1)

These are then sent to `deployability/modules/workflow_engine/workflow_processor.py`, where using `deployability/modules/schemas`, instructions in YAML are received and the schema of the instructions is checked.

The commands are executed in the WorkflowProcessor of the same file, which also handles parallel executions and aborts failed executions.

[WF.drawio.zip](https://github.com/wazuh/wazuh-qa/files/14167559/WF.drawio.zip)


### License

WAZUH Copyright (C) 2015 Wazuh Inc.  (License GPLv2)
