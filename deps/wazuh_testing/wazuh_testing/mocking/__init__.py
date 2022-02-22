import os
from time import sleep

import wazuh_testing
from wazuh_testing.db_interface import global_db
from wazuh_testing.db_interface import agent_db
from wazuh_testing.tools.services import control_service
from wazuh_testing.tools import client_keys


SYSTEM_DATA = {
    'WINDOWS10': {'target': 'WINDOWS10', 'os_name': 'Microsoft Windows Server 2016 Datacenter Evaluation',
                  'os_major': '10', 'os_minor': '0', 'os_platform': 'windows', 'name': 'windows', 'format': 'win'},
    'MAC': {'target': 'MAC', 'os_name': 'Mac OS X', 'os_major': '10', 'os_minor': '15', 'os_platform': 'darwin',
            'name': 'macos-catalina', 'format': 'pkg'},
    'MACS': {'target': 'MAC', 'os_name': 'Mac OS X Server', 'os_major': '5', 'os_minor': '10', 'os_platform': 'darwin',
             "name": "macos-server", 'format': 'pkg'},
    'ARCH': {'target': 'ARCH', 'os_name': 'Arch Linux', 'os_major': '', 'os_minor': '', 'os_platform': '',
             'name': 'archlinux', 'format': 'rpm'},
    'ALAS': {'target': 'Amazon-Linux', 'os_name': 'Amazon Linux AMI', 'os_major': '2018', 'os_minor': '03',
             'os_platform': 'amzn', 'name': 'amazonlinux', 'format': 'rpm'},
    'ALAS2': {'target': 'Amazon-Linux-2', 'os_name': 'Amazon Linux', 'os_major': '2', 'os_minor': '',
              'os_platform': 'amzn', 'name': 'amazonlinux2', 'format': 'rpm'},
    'RHEL8': {'target': 'RHEL8', 'os_name': 'CentOS Linux', 'os_major': '8', 'os_minor': '1', 'os_platform': 'centos',
              'name': 'centos8', 'format': 'rpm'},
    'RHEL7': {'target': 'RHEL7', 'os_name': 'CentOS Linux', 'os_major': '7', 'os_minor': '1', 'os_platform': 'centos',
              'name': 'centos7', 'format': 'rpm'},
    'RHEL6': {'target': 'RHEL6', 'os_name': 'CentOS Linux', 'os_major': '6', 'os_minor': '1', 'os_platform': 'centos',
              'name': 'centos6', 'format': 'rpm'},
    'RHEL5': {'target': 'RHEL5', 'os_name': 'CentOS Linux', 'os_major': '5', 'os_minor': '1', 'os_platform': 'centos',
              'name': 'centos5', 'format': 'rpm'},
    'BIONIC': {'target': 'BIONIC', 'os_name': 'Ubuntu', 'os_major': '18', 'os_minor': '04', 'os_platform': 'ubuntu',
               'name': 'Ubuntu-bionic', 'format': 'deb'},
    'XENIAL': {'target': 'XENIAL', 'os_name': 'Ubuntu', 'os_major': '16', 'os_minor': '04', 'os_platform': 'ubuntu',
               'name': 'Ubuntu-xenial', 'format': 'deb'},
    'TRUSTY': {'target': 'TRUSTY', 'os_name': 'Ubuntu', 'os_major': '14', 'os_minor': '04', 'os_platform': 'ubuntu',
               'name': 'Ubuntu-trusty', 'format': 'deb'},
    'BUSTER': {'target': 'BUSTER', 'os_name': 'Debian GNU/Linux', 'os_major': '10', 'os_minor': '0',
               'os_platform': 'debian', 'name': 'debian10', 'format': 'deb'},
    'STRETCH': {'target': 'STRETCH', 'os_name': 'Debian GNU/Linux', 'os_major': '9', 'os_minor': '0',
                'os_platform': 'debian', 'name': 'debian9', 'format': 'deb'}
}


def set_system(system):
    """Set custom system in global DB Agent info.

    Args:
        system (str): System to set. Available systems in SYSTEM_DATA variable.
    """
    global_db.modify_system(os_name=SYSTEM_DATA[system]['os_name'], os_major=SYSTEM_DATA[system]['os_major'],
                            os_minor=SYSTEM_DATA[system]['os_minor'], name=SYSTEM_DATA[system]['name'])


def create_mocked_agent(name='centos8-agent', ip='127.0.0.1', register_ip='127.0.0.1', internal_key='',
                        os_name='CentOS Linux', os_version='8.4', os_major='8', os_minor='4', os_codename='centos-8',
                        os_build='4.18.0-147.8.1.el8_1.x86_64', os_platform='#1 SMP Thu Apr 9 13:49:54 UTC 2020',
                        os_uname='x86_64', os_arch='x86_64', version='4.2', config_sum='', merged_sum='',
                        manager_host='centos-8', node_name='node01', date_add='1612942494',
                        last_keepalive='253402300799', group='', sync_status='synced', connection_status='active',
                        client_key_secret=None):
    """Mock a new agent creating a new client keys entry, adding it to the global db and creating a new agent id DB.

    Args:
        name (str): Agent name.
        ip (str): Agent IP.
        register_ip (str): IP of the registered agent.
        internal_key (str): Internal key of the agent.
        os_name (str): Name of the OS.
        os_version (str): Version of the OS.
        os_major (str): Major version of the OS supported.
        os_minor (str): Minor version of the OS supported.
        os_codename (str): Codename of the OS.
        os_build (str): Build id of the OS.
        os_platform (str): Platform version of the OS.
        os_uname (str): Version and architecture of the OS.
        os_arch (str): Architecture of the OS.
        version (str): Version of the agent.
        config_sum (str): .
        merged_sum (str): .
        manager_host (str): Name of the manager.
        node_name (str): Name of the node.
        date_add (str): Date of the added/updated agent.
        last_keepalive (str): Last keep alive timestamp reported.
        group (str): Group of the agent.
        sync_status (str): Status of the syncronization.
        connection_status (str): Status of the connection.
        client_key_secret (str): Client secret key.

    Return:
        str: Agent ID.
    """

    # Get new agent_id
    last_id = global_db.get_last_agent_id()
    agent_id = int(last_id) + 1
    agent_id_str = str(agent_id).zfill(3)  # Convert from x to 00x

    client_keys.add_client_keys_entry(agent_id_str, name, ip, client_key_secret)

    # Delete sys_osinfo data and create the new agent
    agent_db.delete_os_info_data(agent_id)
    global_db.create_or_update_agent(agent_id=agent_id_str, name=name, ip=ip, register_ip=register_ip,
                                     internal_key=internal_key, os_name=os_name, os_version=os_version,
                                     os_major=os_major, os_minor=os_minor, os_codename=os_codename, os_build=os_build,
                                     os_platform=os_platform, os_uname=os_uname, os_arch=os_arch, version=version,
                                     config_sum=config_sum, merged_sum=merged_sum, manager_host=manager_host,
                                     node_name=node_name, date_add=date_add, last_keepalive=last_keepalive, group=group,
                                     sync_status=sync_status, connection_status=connection_status)

    # Restart Wazuh-DB before creating new DB
    control_service('restart', daemon='wazuh-db')

    # sleep is needed since, without it, the agent database creation may fail
    sleep(3)

    return agent_id_str


def delete_mocked_agent(agent_id):
    """Delete a mocked agent removing it from the global db, client keys and db file.

    Args:
        agent_id (str): Agent ID.
    """
    # Remove from global db
    global_db.delete_agent(agent_id)

    # Remove agent id DB file
    os.remove(os.path.join(wazuh_testing.DB_PATH, f"{agent_id}.db"))

    # Remove entry from client keys
    client_keys.delete_client_keys_entry(agent_id)
