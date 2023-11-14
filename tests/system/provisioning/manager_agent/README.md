# wazuh-qa

Wazuh - Manager Agents provisioning

## Enviroment description
This enviroment sets a Manager with three (3) agents. Each agent has a especific version. It is designed to allow testing on different versions of the wazuh agent working in conjunction with a specific version of the wazuh manager.

## Setting up the provisioning

To run this provisioning we need to use a **Linux** machine and install the following tools:

- [Docker](https://docs.docker.com/install/)
- [Ansible](https://docs.ansible.com/ansible/latest/installation_guide/intro_installation.html)

## Structure

```bash
manager_agent
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
│   ├── manager-role
│   │   ├── files
│   │   │   └── ossec.conf
│   │   └── tasks
│   │       └── main.yml
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
- **agent#-package**: link to the wazuh agent package  to be installed on each agent host. (currently versions 4.1.5, 4.2.2 and 4.2.5)

## Environment

The base environment defined for Docker provisioning is

- A master node
- Three agents.

| Agent        | Reports to    |
|--------------|---------------|
| wazuh-agent1 | wazuh-manager |
| wazuh-agent2 | wazuh-manager |
| wazuh-agent3 | wazuh-manager |

## Environment management

For running the docker provisioning we must execute the following command:

```shell script
ansible-playbook -i inventory.yml playbook.yml --extra-vars='{"package_repository":"packages", "repository": "4.x", "package_version": "4.4.0", "package_revision": "1"}'
```

To destroy it, the command is:

```shell script
ansible-playbook -i inventory.yml destroy.yml
```

## Example

```shell script
ansible-playbook -i inventory.yml playbook.yml

PLAY [Create our container (Manager)] *********************************************************************************************************************

TASK [Gathering Facts] *************************************************************************************************************************
ok: [localhost]

TASK [Create a network] *************************************************************************************************************************
ok: [localhost]

TASK [docker_container] *************************************************************************************************************************
changed: [localhost]

PLAY [Create our container (Agent1)] **********************************************************************************************************************

TASK [Gathering Facts] **************************************************************************************************************************
ok: [localhost]

TASK [docker_container] **************************************************************************************************************************
changed: [localhost]

PLAY [Create our container (Agent2)] **********************************************************************************************************************

TASK [Gathering Facts] **************************************************************************************************************************
ok: [localhost]

TASK [docker_container] **************************************************************************************************************************
changed: [localhost]

PLAY [Create our container (Agent3)] **********************************************************************************************************************

TASK [Gathering Facts] ***************************************************************************************************************************
ok: [localhost]

TASK [docker_container] ****************************************************************************************************************************
changed: [localhost]

PLAY [Wazuh Manager] ************************************************************************************************************************

TASK [Gathering Facts] ************************************************************************************************************************
ok: [wazuh-manager]

TASK [roles/manager-role : Check and update debian repositories] ******************************************************************************************
changed: [wazuh-manager]

TASK [roles/manager-role : Installing dependencies using apt] *********************************************************************************************
changed: [wazuh-manager]

TASK [roles/manager-role : Clone wazuh repository] ********************************************************************************************************
changed: [wazuh-manager]

TASK [roles/manager-role : Install manager] ***************************************************************************************************************
changed: [wazuh-manager]

TASK [roles/manager-role : Copy ossec.conf file] **********************************************************************************************************
changed: [wazuh-manager]

TASK [roles/manager-role : Set cluster key] ***************************************************************************************************************
changed: [wazuh-manager]

TASK [roles/manager-role : Set Wazuh Manager IP] **********************************************************************************************************
changed: [wazuh-manager]

TASK [roles/manager-role : Stop Wazuh] ********************************************************************************************************************
changed: [wazuh-manager]

TASK [roles/manager-role : Remove client.keys] ************************************************************************************************************
changed: [wazuh-manager]

TASK [roles/manager-role : enable execd debug mode] *******************************************************************************************************
changed: [wazuh-manager]

TASK [roles/manager-role : Register agents] ***************************************************************************************************************
changed: [wazuh-manager]

TASK [roles/manager-role : Start Wazuh] *******************************************************************************************************************
changed: [wazuh-manager]

PLAY [Wazuh Agent1] **********************************************************************************************************************

TASK [Gathering Facts] **********************************************************************************************************************
ok: [wazuh-agent1]

TASK [roles/agent-role : Check and update debian repositories] ********************************************************************************************
changed: [wazuh-agent1]

TASK [roles/agent-role : Installing dependencies using apt] ***********************************************************************************************
changed: [wazuh-agent1]

TASK [roles/agent-role : Create log source] ***************************************************************************************************************
changed: [wazuh-agent1]

TASK [roles/agent-role : Download package] ****************************************************************************************************************
changed: [wazuh-agent1]

TASK [roles/agent-role : Install agent] *******************************************************************************************************************
changed: [wazuh-agent1]

TASK [roles/agent-role : Copy ossec.conf file] ************************************************************************************************************
changed: [wazuh-agent1]

TASK [roles/agent-role : enable execd debug mode] *********************************************************************************************************
changed: [wazuh-agent1]

TASK [roles/agent-role : Remove client.keys] **************************************************************************************************************
changed: [wazuh-agent1]

TASK [roles/agent-role : Register agents] *****************************************************************************************************************
changed: [wazuh-agent1]

TASK [roles/agent-role : Set Wazuh Manager IP] ************************************************************************************************************
changed: [wazuh-agent1]

TASK [roles/agent-role : Restart Wazuh] *******************************************************************************************************************
changed: [wazuh-agent1]

PLAY [Wazuh Agent2] ***************************************************************************************************************************

TASK [Gathering Facts] ***************************************************************************************************************************
ok: [wazuh-agent2]

TASK [roles/agent-role : Check and update debian repositories] ******************************************************************************************** 
changed: [wazuh-agent2]

TASK [roles/agent-role : Installing dependencies using apt] ***********************************************************************************************
changed: [wazuh-agent2]

TASK [roles/agent-role : Create log source] ***************************************************************************************************************
changed: [wazuh-agent2]

TASK [roles/agent-role : Download package] ****************************************************************************************************************
changed: [wazuh-agent2]

TASK [roles/agent-role : Install agent] *******************************************************************************************************************
changed: [wazuh-agent2]

TASK [roles/agent-role : Copy ossec.conf file] ************************************************************************************************************
changed: [wazuh-agent2]

TASK [roles/agent-role : enable execd debug mode] *********************************************************************************************************
changed: [wazuh-agent2]

TASK [roles/agent-role : Remove client.keys] **************************************************************************************************************
changed: [wazuh-agent2]

TASK [roles/agent-role : Register agents] *****************************************************************************************************************
changed: [wazuh-agent2]

TASK [roles/agent-role : Set Wazuh Manager IP] ************************************************************************************************************
changed: [wazuh-agent2]

TASK [roles/agent-role : Restart Wazuh] *******************************************************************************************************************
changed: [wazuh-agent2]

PLAY [Wazuh Agent3] **********************************************************************************************************************

TASK [Gathering Facts] *************************************************************************************************************************
ok: [wazuh-agent3]

TASK [roles/agent-role : Check and update debian repositories] *******************************************************************************************
changed: [wazuh-agent3]

TASK [roles/agent-role : Installing dependencies using apt] ***********************************************************************************************
changed: [wazuh-agent3]

TASK [roles/agent-role : Create log source] ***************************************************************************************************************
changed: [wazuh-agent3]

TASK [roles/agent-role : Download package] ****************************************************************************************************************
changed: [wazuh-agent3]

TASK [roles/agent-role : Install agent] *******************************************************************************************************************
changed: [wazuh-agent3]

TASK [roles/agent-role : Copy ossec.conf file] ************************************************************************************************************
changed: [wazuh-agent3]

TASK [roles/agent-role : enable execd debug mode] *********************************************************************************************************
changed: [wazuh-agent3]

TASK [roles/agent-role : Remove client.keys] **************************************************************************************************************
changed: [wazuh-agent3]

TASK [roles/agent-role : Register agents] *****************************************************************************************************************
changed: [wazuh-agent3]

TASK [roles/agent-role : Set Wazuh Manager IP] ************************************************************************************************************
changed: [wazuh-agent3]

TASK [roles/agent-role : Restart Wazuh] *******************************************************************************************************************
changed: [wazuh-agent3]

PLAY RECAP ************************************************************************************************************************************************
localhost                  : ok=9    changed=4    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0   
wazuh-agent1               : ok=12   changed=11   unreachable=0    failed=0    skipped=0    rescued=0    ignored=0   
wazuh-agent2               : ok=12   changed=11   unreachable=0    failed=0    skipped=0    rescued=0    ignored=0   
wazuh-agent3               : ok=12   changed=11   unreachable=0    failed=0    skipped=0    rescued=0    ignored=0   
wazuh-manager              : ok=13   changed=12   unreachable=0    failed=0    skipped=0    rescued=0    ignored=0   
=============================================================================== 
Playbook run took 0 days, 0 hours, 15 minutes, 47 seconds 

```

```shell script
ansible-playbook -i inventory.yml destroy.yml

PLAY [localhost] **********************************************************************************************************************************************************

TASK [Gathering Facts] ****************************************************************************************************************************************************
ok: [localhost]

TASK [docker_container] ***************************************************************************************************************************************************
changed: [localhost]

TASK [docker_container] ***************************************************************************************************************************************************
changed: [localhost]

TASK [docker_container] ***************************************************************************************************************************************************
changed: [localhost]

TASK [docker_container] ***************************************************************************************************************************************************
changed: [localhost]
PLAY RECAP ****************************************************************************************************************************************************************
localhost                  : ok=5    changed=4    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0   

```
