## Allocation Module

### User documentation

The Allocation module allows you to create and destroy VMs both locally and in AWS, it also gives the possibility of creating macOS VMs on Wazuh infrastructure or PowerPC VMs, as long as you have the necessary permissions to do so. VMs can be AMD64, ARM64, Windows, macOS (Intel and ARM), and PowerPC (CentOS and Debian).

#### Set the environment

The execution of the allocation is carried out through the JobFlow engine, or by executing them manually through commands.
Execution can be done from any operating system.

Initially, you have to install the required Python libraries. We recommend using virtual environments. Follow the technical documentation at https://docs.python.org/3/library/venv.html.

To use this module, you should use a Debian-based system, we recommend using Ubuntu 22.04 for full compatibility, you must have installed at least Python 3.10.12 and pip3 22.0.2

1. Activate the environment:

  ```bash
  source {venv directory}/bin/activate
  ```

2. Clone the `wazuh-qa` repository:

  Navigate to the project directory and switch to the project branch:

  ```bash
  git clone https://github.com/wazuh/wazuh-qa.git
  cd wazuh-qa
  git checkout {project-branch}
  ```

3. Install requirements:

  ```bash
  pip3 install -r deployability/deps/requirements.txt
  ```

4. The module may execute any of these commands:

  - ssh
  - ssh-keygen
  - sshpass
  - cat
  - vagrant
  - chmod

  These commands must be available to run on the Host Operating System.

#### Use the Allocation module through the JobFlow engine

Now, it is possible to use the Worklow engine library to launch the provision module by doing the following steps:

1. Install the JobFlow engine and its launcher:

  While in wazuh-qa:

  ```bash
  cd modules
  pip3 uninstall -y jobflow && pip3 install .
  ```

2. Test Fixture to Execute:

      It will be necessary to create a fixture (yaml file) where the infrastructure, provisioning, and tests to be executed will be declared.

      >Note: It is possible to find some fixture examples in [deployability/modules/jobflow/examples/](../jobflow/examples)

      Example:

      ```bash
      version: 0.1
      description: This YAML file is used to test agents' deployment for DDT1 PoC
      variables:
        agent-os:
          - linux-ubuntu-18.04-amd64
          - linux-ubuntu-20.04-amd64
        manager-os: linux-ubuntu-22.04-amd64
        infra-provider: aws
        working-dir: /tmp/dtt1-poc

      tasks:
        # Unique manager allocate task
        - task: "allocate-manager-{manager-os}"
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
                - label-termination-date: "1d"
                - label-team: "qa"
          cleanup:
            this: process
            with:
              path: python3
              args:
                - modules/allocation/main.py
                - action: delete
                - track-output: "{working-dir}/manager-{manager-os}/track.yaml"

        # Unique agent allocate task
        - task: "allocate-agent-{agent}"
          description: "Allocate resources for the agent."
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
                - label-termination-date: "1d"
                - label-team: "qa"
          foreach:
            - variable: agent-os
              as: agent
          cleanup:
            this: process
            with:
              path: python3
              args:
                - modules/allocation/main.py
                - action: delete
                - track-output: "{working-dir}/agent-{agent}/track.yaml"
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
  python3 -m jobflow {.yaml fixture path}
  ```

  Example

  ```bash
  python3 -m jobflow modules/jobflow/examples/dtt1-agents-poc.yaml
  ```


#### Manual execution of the Allocation module

If one wishes to execute the allocaation module without installing the JobFlow engine, they can proceed by using the launcher ([module/allocation/main.py](main.py)):

1. Create

  While in wazuh-qa/deployability

- Local deployment (Vagrant)

  ```bash
  python3 modules/allocation/main.py --action create --provider '{{ vagrant }}' --size '{{ large }}' --composite-name '{{ composite-name }}' --instance-name '{{ name }}' --inventory-output '{{ inventory }}' --track-output '{{ track }}'

  ```

  >Note: In the case of Vagrant it is mandatory to specify either --instance-name or --label-issue parameters.

  Example:
  ```bash
  python3 modules/allocation/main.py --action create --provider vagrant --size large --composite-name linux-ubuntu-22.04-amd64 --instance-name "ubuntu_2204_amd_large" --inventory-output "/tmp/dtt1-poc/agent-linux-ubuntu-22.04-amd64/inventory.yaml" --track-output "/tmp/dtt1-poc/agent-linux-ubuntu-22.04-amd64/track.yaml"
  ```

  Example 2:
  ```bash
  python3 modules/allocation/main.py --action create --provider vagrant --size micro --composite-name linux-ubuntu-22.04-amd64 --label-issue "https://github.com/wazuh/internal-devel-requests/issues/1115" --inventory-output "/tmp/dtt1-poc/agent-linux-ubuntu-22.04-amd64/inventory.yaml" --track-output "/tmp/dtt1-poc/agent-linux-ubuntu-22.04-amd64/track.yaml"
  ```

- AWS deployment

  ```bash
  python3 modules/allocation/main.py --action create --provider '{{ aws }}' --size '{{ large }}' --composite-name '{{ composite-name }}' --inventory-output '{{ inventory }}' --track-output '{{ track }}' --label-termination-date '{{ termination-date }}' --label-team  '{{ team }}'

  ```

  >Note: In the case of AWS it is mandatory to define two arguments that are not necessary for Vagrant, --label-termination-date and --label-team.
   --label-termination-date: This argument allows you to define the date on which the machine can be deleted. The allowed values are **1d** (where the **1** refers to the number of days the machine is needed) or with the following format **"2024-03-20 21:00:00"**
   --label-team: This argument allows you to set the team that owns the VM to be able to track it. The valid options are: **qa**, **core**, **framework**, **devops**, **frontend**, **operations**, **cloud**, **threat-intel**, **marketing**, **documentation**



  Example:
  ```bash
  python3 modules/allocation/main.py --action create --provider aws --size large --composite-name linux-ubuntu-22.04-amd64 --inventory-output "/tmp/dtt1-poc/agent-linux-ubuntu-22.04-amd64/inventory.yaml" --track-output "/tmp/dtt1-poc/agent-linux-ubuntu-22.04-amd64/track.yaml" --label-termination-date "2024-03-20 21:00:00"  --label-team devops
  ```

  Example 2:
  ```bash
  python3 modules/allocation/main.py --action create --provider aws --size small --composite-name linux-ubuntu-22.04-amd64 --inventory-output "/tmp/dtt1-poc/agent-linux-ubuntu-22.04-amd64/inventory.yaml" --track-output "/tmp/dtt1-poc/agent-linux-ubuntu-22.04-amd64/track.yaml" --label-termination-date "3d"  --label-team devops --label-issue "https://github.com/wazuh/internal-devel-requests/issues/1115"
  ```

  Example 3:
  ```bash
  python3 modules/allocation/main.py --action create --provider aws --size small --composite-name linux-ubuntu-22.04-amd64 --inventory-output "/tmp/dtt1-poc/agent-linux-ubuntu-22.04-amd64/inventory.yaml" --track-output "/tmp/dtt1-poc/agent-linux-ubuntu-22.04-amd64/track.yaml" --label-termination-date "1d"  --label-team devops --instance-name "ubuntu_2204_amd_large"
  ```

2. Delete

  While in wazuh-qa/deployability

  ```bash
  python3 modules/allocation/main.py --action delete --track-output '{{ track }}'

  ```

  Example:
  ```bash
  python3 modules/allocation/main.py --action delete --track-output "/tmp/dtt1-poc/agent-linux-ubuntu-22.04-amd64/track.yaml"
  ```

  >Note: The --track-output argument is mandatory for the delete action because this file contains all information of the VM that will be destroyed

3. Arguments

  - --provider
    This argument allows us to choose on with platform we will deploy our VM. The allowed values are **aws** or **vagrant**.

  - --size
    This argument allows us to choose the resources of the VM. The allowed values are **micro**, **small**, **medium**, and **large**.

    - Vagrant equivalences
      micro: CPU 1 - Memory 1024
      small: CPU 1 - Memory 2048
      medium: CPU 2 - Memory 4096
      large: CPU 4 - Memory 8192

    - AWS equivalences
      micro: t2.small (AMD64) - a1.medium (ARM64)
      small: t3.small (AMD64) - a1.large (ARM64)
      medium: t3a.medium (AMD64) - a1.xlarge (ARM64)
      large: c5ad.xlarge (AMD64) - c6g.xlarge (ARM64)

  - --composite-name
    This argument allows us to choose the OS, version, and architecture of the VM, example: **linux-centos-7-amd64**

  - --action
    This argument defines the action that the module will perform. Allowed values are **create** or **delete**. By default: **create**

  - --ssh-key
    This argument allows us to use a custom ssh key for the VM. <br>
    Considerations:
    - must enter the path where the key is located, with the name of the complete key: **~/.ssh/allocation_test**
    - on the same path you have to have the pair of keys (private and public key with the same name): **~/.ssh/allocation_test** **~/.ssh/allocation_test.pub**
    - In the case of AWS, you must first create the key in the same region where you are going to deploy the instance. It is important that the key in AWS has the same name as your private key file.

  - --custom-provider-config
    This argument allows us to provide a configuration file with all the VM definitions.

  - --track-output
    This argument allows us to define which path we want the track file to write to. By default, it is saved in the instance directory, for example: **/tmp/wazuh-qa/allocation-test-4262/track.yml** <br>
    Valid options:
      - Custom dir: **~/allocation-test**
      - Custom filename: **~/allocation-test/manager-track.yml**
      - Default (without parameter): **\<working-dir>/\<instance-dir>/track.yml**
      - File extension: **.yml** or **.yaml**
      - The file name must contain **track** string for easy identification

    >Note: this argument is mandatory for delete action.

  - --inventory-output
    This argument allows us to define which path we want the inventory file to write to. By default, it is saved in the instance directory, for example: **/tmp/wazuh-qa/allocation-test-4262/inventory.yml** <br>
    Valid options:
      - Custom dir: **~/allocation-test**
      - Custom filename: **~/allocation-test/manager-inventory.yml**
      - Default (without parameter): **\<working-dir>/\<instance-dir>/inventory.yml**
      - File extension: **.yml** or **.yaml**
      - The file name must contain **inventory** string for easy identification

  - --working-dir
    This argument allows us to define in which directory the files referring to the VM will be generated. By default, **/tmp/wazuh-qa**

  - --label-issue
    This argument is mandatory for the Vagrant deploy if the **--instance-name** is not specified. For AWS deploy, it is not mandatory. It allows to create a label to reference the created instance to an issue on GitHub. It has to be a GitHub URL of a Wazuh repository, for example: **https://github.com/wazuh/internal-devel-requests/issues/1008**

  - --label-team
    This argument it is mandatory for AWS deploy, allows you to set the team that owns the VM to be able to track it. The valid options are: **qa**, **core**, **framework**, **devops**, **frontend**, **operations**, **cloud**, **threat-intel**, **marketing**, **documentation**

  - --label-termination-date
    This argument it is mandatory for AWS deploy, allows you to define the date on which the machine can be deleted. The allowed values are **1d** (where the **1** refers to the number of days the machine is needed) or with the following format **"2024-03-20 21:00:00"**

  - --instance-name
    This argument is mandatory for the Vagrant if the **--label-issue** is not specified. It allows us to define a custom name for the instance. In AWS deploy, if this argument is not used, the instance name is defined by other parameters entered, such as --label-issue or --composite-name.
---

### Technical documentation

The allocation module allows creating infrastructure on both AWS and locally (using Vagrant).

Instructions can be initiated from the fixture and executed through the JobFlow engine or executed using Python commands.

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

In the provided fixture fragment, it is evident that to execute the Allocation module launcher ([allocation/main.py](main.py)), the action, provider, size, composite-name, inventory-output, and track-output must be specified.

For manual execution, an example command would be:

```bash
python3 modules/allocation/main.py --action create --provider vagrant --size large --composite-name linux-ubuntu-22.04-amd64 --inventory-output "/tmp/dtt1-poc/agent-linux-ubuntu-22.04-amd64/inventory.yaml" --track-output "/tmp/dtt1-poc/agent-linux-ubuntu-22.04-amd64/track.yaml"
```

#### General-specific functions

- **Launcher** ([/wazuh-qa/deployability/modules/allocation/main.py](main.py)): The entry point of the module. The command line or the JobFlow engine typically invokes this entry point.

- **Module functions** ([/wazuh-qa/deployability/modules/allocation/allocation.py](allocation.py)): Module-specific functions responsible for triggering the allocation.

- **Static functions** ([/wazuh-qa/deployability/modules/allocation/static](static)): Templates and static information for infrastructure creation.

#### Provider-specific functions

- **AWS functions** ([/wazuh-qa/deployability/modules/allocation/aws](aws)): Module-specific functions responsible for triggering the allocation.

- **Vagrant functions** ([/wazuh-qa/deployability/modules/allocation/vagrant](vagrant)): Module-specific functions responsible for triggering the allocation.

- **Generic functions** ([/wazuh-qa/deployability/modules/allocation/generic](generic)): Module-specific functions responsible for triggering the allocation.

#### Each provider will contain

- **Modeler** (`/wazuh-qa/deployability/modules/allocation/{provider}/models.py`)
- **Credentials** (`/wazuh-qa/deployability/modules/allocation/{provider}/credentials.py`)
- **Provider** (`/wazuh-qa/deployability/modules/allocation/{provider}/provider.py`)
- **Information regarding the instance** (`/wazuh-qa/deployability/modules/allocation/{provider}/instance.py`)

#### Diagram

![image](https://github.com/wazuh/wazuh-qa/assets/2949519/c673b3ec-ac6a-4ca0-b625-9f98be422f20)


[Allocation.drawio.zip](https://github.com/user-attachments/files/15792190/Allocation.drawio.zip)

### Known issues

Currently, the Allocation module may encounter the following issues:

1. **Rocky Linux 9 ARM instance fails to start with `micro` size on AWS**

   - **Issue:** When attempting to launch a Rocky Linux 9 ARM instance on AWS using the `micro` size, the instance fails to start. This occurs because the specified `micro` size is not supported by the AMI.
   - **Symptoms:** The Allocator module fails to launch the instance. The error reported says that "The instance configuration for this AWS Marketplace product is not supported".
   - **Workaround:**: This AMI does not support the `micro` size. Choose the `small` size or higher to launch this instance.


### License


WAZUH Copyright (C) 2015 Wazuh Inc. (License GPLv2)
