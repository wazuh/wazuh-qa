## Workflow engine
            
### User documentation     

The test module runs tests on the different components of Wazuh.
It is designed so that you can perform installations, actions on components and uninstallations, performing validations at each step.
This module must receive allocated and provisioned infrastructure. (From Allocation and Provision modules)

This module can be executed as follows:
  A. Installing and using Workflow engine
  B. Direct execution


#### A. Installing and using Workflow engine

The execution of the workflow is done through the installation of its library.

Initially, Python libraries must be installed. we recommended the use of virtual environments. Follow the technical documentation at https://docs.python.org/3/library/venv.html.

1. Create the python environment:

	```bash
   python3 -m venv {environment_name}
	```


2. Activate the environment:

	```bash
	 source {venv directory}/bin/activate
	```

3. Clone the `wazuh-qa` repository:

	Navigate to the project directory and switch to the project branch:

	```bash
   https://github.com/wazuh/wazuh-qa.git
	cd wazuh-qa
	git checkout {project-branch}
	```

4. Install requirements:

	```bash
	pip3 install -r deployability/deps/requirements.txt
	```

5. Install the Workflow engine library and its launcher:

	While in wazuh-qa:

	```bash
	cd modules
	pip3 uninstall -y workflow_engine && pip3 install .
	```

  Run the module by doing the following steps:

6. Test fixture to execute:

      It will be necessary to create a fixture (YAML file) where the infrastructure, provisioning, and tests to be executed will be declared.

      >Note: It is possible to find some fixture examples in '[deployability/modules/workflow_engine/examples/](https://github.com/wazuh/wazuh-qa/tree/master/deployability/modules/workflow_engine/examples)'

      Example:
      
      ```bash
      version: 0.1
      description: This workflow is used to test agents deployment por DDT1 PoC
      variables:
        agents-os:
          - linux-ubuntu-22.04-amd64
        manager-os: 
          - linux-redhat-8-amd64
        infra-provider: vagrant
        working-dir: /tmp/dtt1-poc

      tasks:
        # Generic agent test task
        - task: "run-agent-tests"
          description: "Run tests install for the agent."
          do:
            this: process
            with:
              path: python3
              args:
                - modules/testing/main.py
                - targets:
                  - wazuh-1: "{working-dir}/manager-linux-ubuntu-22.04-amd64/inventory.yaml"
                  - agent-1: "{working-dir}/agent-linux-redhat-8-amd64/inventory.yaml"
                - tests: "install,registration,restart,stop,uninstall"
                - component: "agent"
                - wazuh-version: "4.7.1"
                - wazuh-revision: "40709"
                - live: "True"
          depends-on:
            - "allocate-{agent}"
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

7. Command execution (local):

	Execute the command by referencing the parameters required by the library (launcher).
	
	```bash
	python3 -m workflow_engine {.yaml fixture path} 
	```

	Example

	```bash
	python3 -m workflow_engine modules/workflow_engine/examples/dtt1-agents-poc.yaml
	```

#### B. Direct execution

To execute the testing module without installing the Workflow engine, it can be done by using the launcher ('[module/testing/main.py](https://github.com/wazuh/wazuh-qa/tree/master/deployability/modules/testing/main.py)'):

1. Execution

  While in 'wazuh-qa/deployability'
	
  ```bash
  python3  modules/testing/main.py --wazuh-revision '{{ wazuh_revision }}' --wazuh-version '{{ wazuh_version }}' --component {{ component }} --tests 'install,restart,stop,uninstall' --targets '{"wazuh-1":"{{ inventory }}"}' --targets '{"wazuh-2":"{{ inventory }}"}' --live 'True'
  ```

  Examples:
  ```bash
  python3  modules/testing/main.py --wazuh-revision '40714' --wazuh-version '4.7.3' --component 'manager' --tests 'install,restart,stop,uninstall' --targets '{"wazuh-1":"/tmp/dtt1-poc/manager-linux-ubuntu-22.04-amd64/inventory.yml"}' --targets '{"wazuh-2":"/tmp/dtt1-poc/manager-linux-redhat-8-amd64/inventory.yml"}' --live 'True'
  ```

  ```bash
  python3  modules/testing/main.py --wazuh-revision '40714' --wazuh-version '4.7.3' --component 'agent' --tests 'install,registration,restart,stop,uninstall' --targets '{"wazuh-1":"/tmp/dtt1-poc/manager-linux-ubuntu-22.04-amd64/inventory.yml"}' --targets '{"agent-1":"/tmp/dtt1-poc/agent-linux-redhat-8-amd64/inventory.yml"}' --targets '{"agent-2":"/tmp/dtt1-poc/agent-linux-redhat-9-amd64/inventory.yml"}' --targets '{"agent-3":"/tmp/dtt1-poc/agent-linux-centos-7-amd64/inventory.yml"}' --live 'True'
  ```

  #### To be considered:
  wazuh-1: This is the master node
  wazuh-{number}: They are the workers
  agent-{number}: They are the agents

  >If the manager component is tested, 'wazuh-' components must be entered in target.
   If the agent component is tested, there must be a master and the rest must be 'agent-'s

---

### Technical documentation

`Workflow engine` is the orchestrator of the deployability test architecture.

Its function is to allow the ordered and structured execution in steps of allocation, provision, and testing.

`The Workflow engine` receives instructions through a `YAML document`, the structure of which can be exemplified in tests found in:
'[wazuh-qa/deployability/modules/workflow_engine/examples](https://github.com/wazuh/wazuh-qa/tree/master/deployability/modules/workflow_engine/examples)'

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

```bash
  - task: "run-agent-tests"
    description: "Run tests install for the agent."
    do:
      this: process
      with:
        path: python3
        args:
          - modules/testing/main.py
          - targets:
            - wazuh-1: "{working-dir}/manager-linux-ubuntu-22.04-amd64/inventory.yaml"
            - agent-1: "{working-dir}/agent-linux-redhat-8-amd64/inventory.yaml"
          - tests: "install,registration,restart,stop,uninstall"
          - component: "agent"
          - wazuh-version: "4.7.1"
          - wazuh-revision: "40709"
          - live: "True"
    depends-on:
      - "allocate-{agent}"
      - "allocate-manager"
```
In the exposed fixture fragment, it can be observed that for the execution of the testing module launcher ('[testing/main.py](https://github.com/wazuh/wazuh-qa/tree/master/deployability/modules/testing/main.py)'), it is necessary to provide the inventory, dependencies, component, tests to execute, Wazuh version, Wazuh revision, and whether the repository is live or not (if not, it will look for information in packages-dev pre-release).

These tasks are executed by the `Workflow engine` launcher installed as workflow_engine library in your virtual environment.

This launcher receives the parameters, sets up the test logs, and proceeds with the ordered execution.

The parameters sent from the launcher are processed by '[deployability/modules/workflow_engine/models.py](https://github.com/wazuh/wazuh-qa/blob/master/deployability/modules/workflow_engine/models.py)', which checks the nature of the parameters sent and filters out incorrect parameters.

![image](https://github.com/wazuh/wazuh-qa/assets/125690423/32aa77b7-f294-41ac-af93-db8a084dbad1)

These are then sent to '[deployability/modules/workflow_engine/workflow_processor.py](https://github.com/wazuh/wazuh-qa/blob/master/deployability/modules/workflow_engine/workflow_processor.py)', where using '[deployability/modules/workflow_engine/schemas](https://github.com/wazuh/wazuh-qa/tree/master/deployability/modules/workflow_engine/schemas)', instructions in YAML are received and the schema of the instructions is checked.

The commands are executed in the [Workflow processor](https://github.com/wazuh/wazuh-qa/blob/master/deployability/modules/workflow_engine/workflow_processor.py) of the same file, which also handles parallel executions and aborts failed executions.

[WF.drawio.zip](https://github.com/wazuh/wazuh-qa/files/14167559/WF.drawio.zip)

The test module must recieve the infrastructure generated and provisioned by the allocation and provision modules. The module can execute actions on the hosts as well as perform the necessary validation.

Testing of the manager component includes:
`install`, `restart`, `stop` and `uninstall`
Install should come at the beginning and uninstall at the end, other tests can change their order

Testing of the agent component includes:
`install`, `registration`, `restart`, `stop` and `uninstall`
Install must come at the beginning followed by registration Uninstall must come at the end and the other tests can change their order

### License

WAZUH Copyright (C) 2015 Wazuh Inc.  (License GPLv2)
