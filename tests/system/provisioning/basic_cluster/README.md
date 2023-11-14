# wazuh-qa

Wazuh - Basic cluster provisioning

## Setting up the provisioning

To run this provisioning we need to use a **Linux** machine and install the following tools:

- [Docker](https://docs.docker.com/install/)
- [Ansible](https://docs.ansible.com/ansible/latest/installation_guide/intro_installation.html)

## Structure

```bash
basic_cluster
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
- Three agents, each connected to a different manager.

| Agent        | Reports to    |
|--------------|---------------|
| wazuh-agent1 | wazuh-master  |
| wazuh-agent2 | wazuh-worker1 |
| wazuh-agent3 | wazuh-worker2 |

## Environment management

For running the docker provisioning we must execute the following command:

```shell script
ansible-playbook -i inventory.yml playbook.yml --extra-vars='{"package_repository":"packages", "repository": "4.x", "package_version": "4.4.0", "package_revision": "1", "wazuh_qa_branch":"v4.3.0-rc1"}'
```

To destroy it, the command is:

```shell script
ansible-playbook -i inventory.yml destroy.yml
```

## Example

```shell script
ansible-playbook -i inventory.yml playbook.yml

PLAY [Create our container (Master)] **************************************************************************************************************************************

TASK [Gathering Facts] ****************************************************************************************************************************************************
ok: [localhost]

TASK [Create a network] ***************************************************************************************************************************************************
ok: [localhost]

TASK [docker_container] ***************************************************************************************************************************************************
changed: [localhost]

PLAY [Create our container (Worker1)] *************************************************************************************************************************************

TASK [Gathering Facts] ****************************************************************************************************************************************************
ok: [localhost]

TASK [docker_container] ***************************************************************************************************************************************************
changed: [localhost]

PLAY [Create our container (Worker2)] *************************************************************************************************************************************

TASK [Gathering Facts] ****************************************************************************************************************************************************
ok: [localhost]

TASK [docker_container] ***************************************************************************************************************************************************
changed: [localhost]

PLAY [Create our container (Agent1)] **************************************************************************************************************************************

TASK [Gathering Facts] ****************************************************************************************************************************************************
ok: [localhost]

TASK [docker_container] ***************************************************************************************************************************************************
changed: [localhost]

PLAY [Create our container (Agent2)] **************************************************************************************************************************************

TASK [Gathering Facts] ****************************************************************************************************************************************************
ok: [localhost]

TASK [docker_container] ***************************************************************************************************************************************************
changed: [localhost]

PLAY [Create our container (Agent3)] **************************************************************************************************************************************

TASK [Gathering Facts] ****************************************************************************************************************************************************
ok: [localhost]

TASK [docker_container] ***************************************************************************************************************************************************
changed: [localhost]

PLAY [Wazuh Master] *******************************************************************************************************************************************************

TASK [Gathering Facts] ****************************************************************************************************************************************************
ok: [wazuh-master]

TASK [roles/master-role : Installing dependencies using apt] **************************************************************************************************************
changed: [wazuh-master]

TASK [roles/master-role : Clone wazuh repository] *************************************************************************************************************************
changed: [wazuh-master]

TASK [roles/master-role : Install master] *********************************************************************************************************************************
changed: [wazuh-master]

TASK [roles/master-role : Copy ossec.conf file] ***************************************************************************************************************************
changed: [wazuh-master]

TASK [roles/master-role : Set cluster key] ********************************************************************************************************************************
changed: [wazuh-master]

TASK [roles/master-role : Set Wazuh Master IP] ****************************************************************************************************************************
changed: [wazuh-master]

TASK [roles/master-role : Stop Wazuh] *************************************************************************************************************************************
changed: [wazuh-master]

TASK [roles/master-role : Remove client.keys] *****************************************************************************************************************************
changed: [wazuh-master]

TASK [roles/master-role : Register agents] ********************************************************************************************************************************
changed: [wazuh-master]

TASK [roles/master-role : Start Wazuh] ************************************************************************************************************************************
changed: [wazuh-master]

PLAY [Wazuh Worker1] ******************************************************************************************************************************************************

TASK [Gathering Facts] ****************************************************************************************************************************************************
ok: [wazuh-worker1]

TASK [roles/worker-role : Installing dependencies using apt] **************************************************************************************************************
changed: [wazuh-worker1]

TASK [roles/worker-role : Clone wazuh repository] *************************************************************************************************************************
changed: [wazuh-worker1]

TASK [roles/worker-role : Install worker] *********************************************************************************************************************************
changed: [wazuh-worker1]

TASK [roles/worker-role : Copy ossec.conf file] ***************************************************************************************************************************
changed: [wazuh-worker1]

TASK [roles/worker-role : Set cluster key] ********************************************************************************************************************************
changed: [wazuh-worker1]

TASK [roles/worker-role : Set Wazuh Worker name] **************************************************************************************************************************
changed: [wazuh-worker1]

TASK [roles/worker-role : Set Wazuh Worker IP] ****************************************************************************************************************************
changed: [wazuh-worker1]

TASK [roles/worker-role : Restart Wazuh] **********************************************************************************************************************************
changed: [wazuh-worker1]

PLAY [Wazuh Worker2] ******************************************************************************************************************************************************

TASK [Gathering Facts] ****************************************************************************************************************************************************
ok: [wazuh-worker2]

TASK [roles/worker-role : Installing dependencies using apt] **************************************************************************************************************
changed: [wazuh-worker2]

TASK [roles/worker-role : Clone wazuh repository] *************************************************************************************************************************
changed: [wazuh-worker2]

TASK [roles/worker-role : Install worker] *********************************************************************************************************************************
changed: [wazuh-worker2]

TASK [roles/worker-role : Copy ossec.conf file] ***************************************************************************************************************************
changed: [wazuh-worker2]

TASK [roles/worker-role : Set cluster key] ********************************************************************************************************************************
changed: [wazuh-worker2]

TASK [roles/worker-role : Set Wazuh Worker name] **************************************************************************************************************************
changed: [wazuh-worker2]

TASK [roles/worker-role : Set Wazuh Worker IP] ****************************************************************************************************************************
changed: [wazuh-worker2]

TASK [roles/worker-role : Restart Wazuh] **********************************************************************************************************************************
changed: [wazuh-worker2]

PLAY [Wazuh Agent1] *******************************************************************************************************************************************************

TASK [Gathering Facts] ****************************************************************************************************************************************************
ok: [wazuh-agent1]

TASK [roles/agent-role : Installing dependencies using apt] ***************************************************************************************************************
changed: [wazuh-agent1]

TASK [roles/agent-role : Clone wazuh repository] **************************************************************************************************************************
changed: [wazuh-agent1]

TASK [roles/agent-role : Install agent] ***********************************************************************************************************************************
changed: [wazuh-agent1]

TASK [roles/agent-role : Copy ossec.conf file] ****************************************************************************************************************************
changed: [wazuh-agent1]

TASK [roles/agent-role : Remove client.keys] ******************************************************************************************************************************
changed: [wazuh-agent1]

TASK [roles/agent-role : Register agents] *********************************************************************************************************************************
changed: [wazuh-agent1]

TASK [roles/agent-role : Set Wazuh Manager IP] ****************************************************************************************************************************
changed: [wazuh-agent1]

TASK [roles/agent-role : Restart Wazuh] ***********************************************************************************************************************************
changed: [wazuh-agent1]

PLAY [Wazuh Agent2] *******************************************************************************************************************************************************

TASK [Gathering Facts] ****************************************************************************************************************************************************
ok: [wazuh-agent2]

TASK [roles/agent-role : Installing dependencies using apt] ***************************************************************************************************************
changed: [wazuh-agent2]

TASK [roles/agent-role : Clone wazuh repository] **************************************************************************************************************************
changed: [wazuh-agent2]

TASK [roles/agent-role : Install agent] ***********************************************************************************************************************************
changed: [wazuh-agent2]

TASK [roles/agent-role : Copy ossec.conf file] ****************************************************************************************************************************
changed: [wazuh-agent2]

TASK [roles/agent-role : Remove client.keys] ******************************************************************************************************************************
changed: [wazuh-agent2]

TASK [roles/agent-role : Register agents] *********************************************************************************************************************************
changed: [wazuh-agent2]

TASK [roles/agent-role : Set Wazuh Manager IP] ****************************************************************************************************************************
changed: [wazuh-agent2]

TASK [roles/agent-role : Restart Wazuh] ***********************************************************************************************************************************
changed: [wazuh-agent2]

PLAY [Wazuh Agent3] *******************************************************************************************************************************************************

TASK [Gathering Facts] ****************************************************************************************************************************************************
ok: [wazuh-agent3]

TASK [roles/agent-role : Installing dependencies using apt] ***************************************************************************************************************
changed: [wazuh-agent3]

TASK [roles/agent-role : Clone wazuh repository] **************************************************************************************************************************
changed: [wazuh-agent3]

TASK [roles/agent-role : Install agent] ***********************************************************************************************************************************
changed: [wazuh-agent3]

TASK [roles/agent-role : Copy ossec.conf file] ****************************************************************************************************************************
changed: [wazuh-agent3]

TASK [roles/agent-role : Remove client.keys] ******************************************************************************************************************************
changed: [wazuh-agent3]

TASK [roles/agent-role : Register agents] *********************************************************************************************************************************
changed: [wazuh-agent3]

TASK [roles/agent-role : Set Wazuh Manager IP] ****************************************************************************************************************************
changed: [wazuh-agent3]

TASK [roles/agent-role : Restart Wazuh] ***********************************************************************************************************************************
changed: [wazuh-agent3]

PLAY RECAP ****************************************************************************************************************************************************************
localhost                  : ok=13   changed=6    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0   
wazuh-agent1               : ok=9    changed=8    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0   
wazuh-agent2               : ok=9    changed=8    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0   
wazuh-agent3               : ok=9    changed=8    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0   
wazuh-master               : ok=11   changed=10   unreachable=0    failed=0    skipped=0    rescued=0    ignored=0   
wazuh-worker1              : ok=9    changed=8    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0   
wazuh-worker2              : ok=9    changed=8    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0   

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

TASK [docker_container] ***************************************************************************************************************************************************
changed: [localhost]

TASK [docker_container] ***************************************************************************************************************************************************
changed: [localhost]

PLAY RECAP ****************************************************************************************************************************************************************
localhost                  : ok=7    changed=6    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0   

```
