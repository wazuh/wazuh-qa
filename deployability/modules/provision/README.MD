## Provision module

### User documentation

The Provision module installs libraries, dependencies and applications on the allocated infrastructure (From Allocation module)

This module can be executed as follows:
  A. Installing and using the JobFlow engine
  B. Direct execution

#### A. Installing and using the JobFlow engine

The execution of the JobFlow engine is done through the installation of its library.

Initially, Python libraries must be installed. we recommended the use of virtual environments. Follow the technical documentation at https://docs.python.org/3/library/venv.html.

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

  Run the module by doing the following steps:

6. Test fixture to execute:

      It is required to create a fixture (YAML file) where the infrastructure, provisioning, and tests to be executed is declared.

      >Note: You can find some fixture examples in '[deployability/modules/jobflow/examples/](https://github.com/wazuh/wazuh-qa/tree/master/deployability/modules/jobflow/examples)'

      Example:

      ```bash
      version: 0.1
      description: This YAML is used to provision agent hosts for DDT1 PoC
      variables:
        agents-os:
          - linux-ubuntu-22.04-amd64
        infra-provider: vagrant
        working-dir: /tmp/dtt1-poc

      tasks:
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

        - task: "provision-install-{agent}"
          description: "Provision resources for the {agent} agent."
          do:
            this: process
            with:
              path: python3
              args:
                - modules/provision/main.py
                - inventory: "{working-dir}/agent-{agent}/inventory.yaml"
                - dependencies:
                  - agent: "{working-dir}/agent-{agent}/inventory.yaml"
                - install:
                  - component: curl
                  - component: python
                    type: source
                    version: "{python-version}"
                  - component: virtualenv
                    type: pip
                  - component: deps/requirements.txt
                    type: pip
                  - component: pyyaml
                    type: pip
                    version: 6.0.1
          depends-on:
            - "allocate-{agent}"
          foreach:
            - variable: agents-os
              as: agent
      ```

      Following the schema of the example:

      Configure the following parameters depending on your allocation:

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

      >Note: In args, configure the launcher's path correctly (main.py files in each module), and to fill `depends-on`, consider the steps of your provision (allocation and provision)

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

To execute the Allocation module without installing the JobFlow engine, you can use the launcher ('[module/provision/main.py](https://github.com/wazuh/wazuh-qa/tree/master/deployability/modules/provision/main.py)'):

1. Execution

  While in wazuh-qa/deployability

  ```bash
  python3 module/provision/main.py --inventory-manager { inventory .yaml} --install "{'component': '{component}', 'type': '{type}', 'version': '{version}'}"
  ```

  Example:
  ```bash
  python3 module/provision/main.py --inventory-manager /tmp/dtt1-poc/manager-linux-ubuntu-22.04-amd64/inventory.yaml --install "{'component': 'pyyaml', 'type': 'pip', 'version' : '6.0.1'}"
  ```

---

### Technical documentation

The `provision module` allows for the installation and uninstallation of libraries, dependencies, and applications in the infrastructure.

It can receive instructions either through the command line or be mediated through the JobFlow engine.

In both cases, the following information is required:

```bash
  - task: "provision-install-{agent}"
    description: "Provision resources for the {agent} agent."
    do:
      this: process
      with:
        path: python3
        args:
          - modules/provision/main.py
          - inventory: "{working-dir}/agent-{agent}/inventory.yaml"
          - dependencies:
            - agent: "{working-dir}/agent-{agent}/inventory.yaml"
          - install:
            - component: curl
            - component: python
              type: source
              version: "{python-version}"
            - component: virtualenv
              type: pip
            - component: deps/requirements.txt
              type: pip
            - component: pyyaml
              type: pip
              version: 6.0.1
    depends-on:
      - "allocate-{agent}"
    foreach:
      - variable: agents-os
        as: agent
```

The snippet obtained from a JobFlow fixture highlights the parameters necessary for its operation. These include the inventory path, the dependency/library to install, and the installation type.

It requires an infrastructure on which to perform its actions.

The module is composed of:

- Launcher ('[/wazuh-qa/deployability/modules/provision/main.py](https://github.com/wazuh/wazuh-qa/tree/master/deployability/modules/provision/main.py)')
  Entry point for the workflow or the user who wishes to execute a provision.

- Parameter validator ('[/wazuh-qa/deployability/modules/provision/models.py](https://github.com/wazuh/wazuh-qa/tree/master/deployability/modules/provision/models.py)')
  Validator for parameters entered by the JobFlow engine or the user.

- Module functions ('[/wazuh-qa/deployability/modules/provision/provision.py](https://github.com/wazuh/wazuh-qa/tree/master/deployability/modules/provision/provision.py)')
  Module-specific functions responsible for triggering the provision.

- Component type categorizer ('[/wazuh-qa/deployability/modules/provision/component_type.py](https://github.com/wazuh/wazuh-qa/tree/master/deployability/modules/provision/component_type.py)')
  Allows obtaining and expanding data based on initially received parameters.

- Executor ('[/wazuh-qa/deployability/modules/provision/actions.py](https://github.com/wazuh/wazuh-qa/tree/master/deployability/modules/provision/actions.py)')
  Executes the provision using Actions in the generic module.

- Utils ('[/wazuh-qa/deployability/modules/provision/utils.py](https://github.com/wazuh/wazuh-qa/tree/master/deployability/modules/provision/utils.py)')
  Enables reading and changing the format of YAML files to executable formats.


![image](https://github.com/wazuh/wazuh-qa/assets/2949519/326c1198-79a9-4098-9a52-d35c7065d629)


[Provision.drawio.zip](https://github.com/user-attachments/files/15788313/Provision.drawio.zip)


### License

WAZUH Copyright (C) 2015 Wazuh Inc. (License GPLv2)
