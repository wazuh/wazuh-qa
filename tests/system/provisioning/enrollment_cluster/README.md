# wazuh-qa

Wazuh - Basic cluster provisioning

## Setting up the provisioning

To run this provisioning we need to use a **Linux** machine and install the following tools:

- [Docker](https://docs.docker.com/install/)
- [Ansible](https://docs.ansible.com/ansible/latest/installation_guide/intro_installation.html)

## Structure

```bash
enrollment_cluster
├── ansible.cfg
├── destroy.yml
├── inventory.yml
├── playbook.yml
├── README.md
├── roles
│   ├── agent-role
│   │   ├── files
│   │   │   └── ossec.conf
│   │   └── tasks
│   │       └── main.yml
│   ├── master-role
│   │   ├── files
│   │   │   └── ossec.conf
│   │   └── tasks
│   │       └── main.yml
│   └── worker-role
│       ├── files
│       │   └── ossec.conf
│       └── tasks
│           └── main.yml
└── vars
    ├── configurations.yml
    └── main.yml
```

#### ansible.cfg

Ansible configuration file in the current directory. In this file, we setup the configuration of Ansible for this
provisioning.

#### destroy.yml

In this file we will specify that we want to shut down the docker machines in our environment.

##### inventory.yml

File containing the inventory of machines in our environment. In this file we will set the connection method and its
python interpreter

##### playbook.yml

Here we will write the commands to be executed in order to use our environment

##### roles

Folder with all the general roles that could be used for start our environment. Within each role we can find the
following structure:

- **files**: Configuration files to be applied when the environment is setting up.
- **tasks**: Main tasks to be performed for each role

#### Vars

This folder contains the variables used to configure our environment. Variables like the cluster key or the agent key.

## Environment

The base environment defined for Docker provisioning is

- A master node
- Two workers nodes
- One agent ready to start the enrollment process with the `worker1` node when `wazuh-agent` starts.

## Environment management

For running the docker provisioning we must execute the following command:

```shell script
ansible-playbook -i inventory.yml playbook.yml --extra-vars='{"wazuh_branch": "PUT YOUT wazuh/wazuh BRANCH HERE"}'
```

To destroy it, the command is:

```shell script
ansible-playbook -i inventory.yml destroy.yml
```
