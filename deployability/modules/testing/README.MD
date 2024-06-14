## Testing Module

### User documentation

The test module runs tests on the different components of Wazuh.
It is designed so that you can perform installations, actions on components and uninstallations, performing validations at each step.
This module must receive allocated and provisioned infrastructure. (From Allocation and Provision modules)

This module can be executed as follows:
  A. Installing and using the JobFlow engine
  B. Direct execution


#### A. Installing and using the JobFlow engine

The execution of the JobFlow engine is done through the installation of its library.

Initially, Python libraries must be installed, we recommended the use of virtual environments. Follow the technical documentation at https://docs.python.org/3/library/venv.html.

To use this module, you should use a Debian-based system, we recommend using Ubuntu 22.04 for full compatibility, you must have installed at least Python 3.10.12 and pip3 22.0.2

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
   git clone https://github.com/wazuh/wazuh-qa.git
	cd wazuh-qa
	git checkout {project-branch}
	```

4. Install requirements:

	```bash
	pip3 install -r deployability/deps/requirements.txt
	```

5. Install the JobFlow engine and its launcher:

	While in wazuh-qa:

	```bash
	cd modules
	pip3 uninstall -y jobflow && pip3 install .
	```

6. The module may execute any of these commands:

  - ssh
  - scp

  These commands must be available to run on the Host Operating System.

  Run the module by doing the following steps:

7. Test fixture to execute:

      It will be necessary to create a fixture (YAML file) where the infrastructure, provisioning, and tests to be executed will be declared.

      >Note: It is possible to find some fixture examples in '[deployability/modules/jobflow/examples/](https://github.com/wazuh/wazuh-qa/tree/master/deployability/modules/jobflow/examples)'

      Example:

      ```bash
      version: 0.1
      description: This YAML is used to test agents' deployment for DDT1 PoC
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
	python3 -m jobflow {.yaml fixture path}
	```

	Example

	```bash
	python3 -m jobflow modules/jobflow/examples/dtt1-agents-poc.yaml
	```

#### B. Direct execution

To execute the testing module without installing the JobFlow engine, it can be done by using the launcher ('[module/testing/main.py](https://github.com/wazuh/wazuh-qa/tree/master/deployability/modules/testing/main.py)'):

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
   If the agent component is tested, there must be a master and the rest must be 'agent-'

---

### Technical documentation

The testing module allows the execution of tests on agents and central components.

Instructions can be received from the fixture and executed through the JobFlow engine or run through commands on an already provisioned infrastructure.

In both cases, the following information will be required:

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
          - wazuh-version: "4.7.3"
          - wazuh-revision: "40714"
          - live: "True"
    depends-on:
      - "allocate-{agent}"
      - "allocate-manager"
```
In the exposed fixture fragment, the execution of the testing module launcher (`testing/main.py`), it is necessary to provide the inventory, dependencies, component, tests to execute, Wazuh version, Wazuh revision, and whether the repository is live or not (if not, it will look for information in packages-dev pre-release).

For manual execution, an example command would be:

  ```bash
  python3  modules/testing/main.py --wazuh-revision '40714' --wazuh-version '4.7.3' --component 'agent' --tests 'install,registration,restart,stop,uninstall' --targets '{"wazuh-1":"/tmp/dtt1-poc/manager-linux-ubuntu-22.04-amd64/inventory.yml"}' --targets '{"agent-1":"/tmp/dtt1-poc/agent-linux-redhat-8-amd64/inventory.yml"}' --live 'True'
  ```

The module is composed of:

- **Launcher** ('[/wazuh-qa/deployability/modules/testing/main.py](https://github.com/wazuh/wazuh-qa/tree/master/deployability/modules/testing/main.py)'): Entry point for the workflow or the user who wishes to execute a test.

- **Parameter validator** ('[/wazuh-qa/deployability/modules/testing/models.py](https://github.com/wazuh/wazuh-qa/tree/master/deployability/modules/testing/models.py)'): Validator for parameters entered by the JobFlow or the user.

- **Module functions** ('[/wazuh-qa/deployability/modules/testing/testing.py](https://github.com/wazuh/wazuh-qa/tree/master/deployability/modules/testing/testing.py)'): Module-specific functions responsible for triggering the test.

- **Executor** ('[/wazuh-qa/deployability/modules/provision/actions.py](https://github.com/wazuh/wazuh-qa/tree/master/deployability/modules/provision/actions.py)'): Executes the provision using Actions in the generic module.

- **Playbooks** ('[/wazuh-qa/deployability/modules/tests/playbooks](https://github.com/wazuh/wazuh-qa/tree/master/deployability/modules/tests/playbooks)'): Contains setup, execution, and post-test cleanup playbooks.

- **Tests** ('[/wazuh-qa/deployability/modules/tests](https://github.com/wazuh/wazuh-qa/tree/master/deployability/modules/tests/)'): Contains the test_agent and test_manager directories where the tests to be executed are located.

- **Helpers** ('[/wazuh-qa/deployability/modules/tests/helpers](https://github.com/wazuh/wazuh-qa/tree/master/deployability/modules/tests/helpers)'): Contains files that enable the execution of the test.

- **Conftest** ('[/wazuh-qa/deployability/modules/tests/conftest.py](https://github.com/wazuh/wazuh-qa/tree/master/deployability/modules/tests/conftest.py)'): Contains information that will be transferred from the parameter validator to the tests.


![image](https://github.com/wazuh/wazuh-qa/assets/2949519/f2c08ca6-5505-40d7-a9eb-6ab37b3d1ba5)


The testing module receives the infrastructure generated and provisioned by the allocation and provision modules. The module has the ability to execute actions on the hosts as well as perform the necessary validation.

[Testing.drawio.zip](https://github.com/user-attachments/files/15792385/Testing.drawio.zip)

The test module must recieve the infrastructure generated and provisioned by the allocation and provision modules. The module can execute actions on the hosts as well as perform the necessary validation.

Testing of the manager component includes:
`install`, `restart`, `stop` and `uninstall`
Install should come at the beginning and uninstall at the end, other tests can change their order

Testing of the agent component includes:
`install`, `registration`, `restart`, `stop` and `uninstall`
Install must come at the beginning followed by registration Uninstall must come at the end and the other tests can change their order

### License

WAZUH Copyright (C) 2015 Wazuh Inc.  (License GPLv2)
