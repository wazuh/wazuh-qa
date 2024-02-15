## Provision module

### User documentation     
   
The execution of the Provision is done through the installation of the library Worfklow library or launching the module using python command. The execution can be done from any operating system.

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
  pip3 install -r /deployability/deps/requirements.txt
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
          - windows-11-amd64
          - macos-ventura-13.04-amd64
          - linux-centos-7-arm64
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
                - testing/main.py
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
                - testing/main.py
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
      
        # Unique manager allocate task
        - task: "allocate-manager"
          description: "Allocate resources for the manager."
          do:
            this: process
            with:
              path: python3
              args:
                - allocation/main.py
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
                - allocation/main.py
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
                - provision/main.py
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
                - provision/main.py
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
                - allocation/main.py
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
                - allocation.py
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


If one wishes to execute the provision module without installing the workflow engine, they can proceed by using the launcher (module/provision/main.py):

1. Execution

  While in wazuh-qa/deployability

  ```bash
  python3 module/provision/main.py --inventory-manager { inventory .yaml} --install "{'component': '{component}', 'type': '{type}'}" 
  ```

  Example:
  ```bash
  python3 module/provision/main.py --inventory-manager /tmp/dtt1-poc/manager-linux-ubuntu-22.04-amd64/inventory.yaml --install "{'component': 'wazuh-manager', 'type': 'package'}" 
  ```

---

### Technical documentation

The `provision module` allows for the installation and uninstallation of libraries, dependencies, and applications in the infrastructure.

It can receive instructions either through the command line or be mediated through the Workflow Engine.

In both cases, the following information is required:

```bash
  - task: "provision-manager"
    description: "Provision the manager."
    do:
      this: process
      with:
        path: python3
        args:
          - provision.py
          - inventory-manager: "{working-dir}/manager-{manager-os}/inventory.yaml"
          - install:
            - component: wazuh-manager
              type: package
```

The snippet obtained from a Workflow fixture highlights the parameters necessary for its operation. These include the inventory path, the component to install, and the installation type.

Of course, it requires an infrastructure on which to perform its actions.

The module is composed of:

- Launcher (/wazuh-qa/deployability/modules/provision/main.py)
  Entry point for the workflow or the user who wishes to execute a provision.

- Parameter validator (/wazuh-qa/deployability/modules/provision/models.py)
  Validator for parameters entered by the Workflow or the user.

- Module functions (/wazuh-qa/deployability/modules/provision/provision.py)
  Module-specific functions responsible for triggering the provision.

- Component type categorizer (/wazuh-qa/deployability/modules/provision/component_type.py)
  Allows obtaining and expanding data based on initially received parameters.

- Executor (/wazuh-qa/deployability/modules/provision/actions.py)
  Executes the provision using Actions in the generic module.

- Utils (/wazuh-qa/deployability/modules/provision/utils.py)
  Enables reading and changing the format of YAML files to executable formats.


![image](https://github.com/wazuh/wazuh-qa/assets/125690423/e06fb59c-6497-4396-b20c-a21a68a5e883)

 
[Provision.drawio.zip](https://github.com/wazuh/wazuh-qa/files/14241269/Provision.drawio.zip)


### License

WAZUH Copyright (C) 2015 Wazuh Inc. (License GPLv2)