import os
from time import sleep

import wazuh_testing
from wazuh_testing.db_interface import global_db
from wazuh_testing.db_interface import agent_db
from wazuh_testing.tools.services import control_service
from wazuh_testing.tools import client_keys
from wazuh_testing.tools.file import remove_file


SYSTEM_DATA = {
    'WINDOWS_XP': {'os_name': 'Microsoft Windows XP', 'os_major': '10', 'os_minor': '0',
                   'os_platform': 'windows', 'name': 'windows_xp', 'os_version': '1000'},
    'WINDOWS_VISTA': {'os_name': 'Microsoft Windows Vista', 'os_major': '10', 'os_minor': '0',
                      'os_platform': 'windows', 'name': 'windows_vista', 'os_version': '1000'},
    'WINDOWS_7': {'os_name': 'Microsoft Windows 7', 'os_major': '10', 'os_minor': '0',
                  'os_platform': 'windows', 'name': 'windows_7', 'os_version': '1000'},
    'WINDOWS_8': {'os_name': 'Microsoft Windows 8', 'os_major': '10', 'os_minor': '0',
                  'os_platform': 'windows', 'name': 'windows_8', 'os_version': '1000'},
    'WINDOWS_8_1': {'os_name': 'Microsoft Windows 8.1', 'os_major': '10', 'os_minor': '0',
                    'os_platform': 'windows', 'name': 'windows_8_1', 'os_version': '1000'},
    'WINDOWS_10': {'os_name': 'Microsoft Windows 10', 'os_major': '10', 'os_minor': '0',
                   'os_platform': 'windows', 'name': 'windows_10', 'os_version': '1000'},
    'WINDOWS_11': {'os_name': 'Microsoft Windows 11', 'os_major': '10', 'os_minor': '0',
                   'os_platform': 'windows', 'name': 'windows_11', 'os_version': '1000'},
    'WINDOWS_SERVER_2003': {'os_name': 'Microsoft Windows Server 2003', 'os_major': '10', 'os_minor': '0',
                            'os_platform': 'windows', 'name': 'windows_server_2013', 'os_version': '1000'},
    'WINDOWS_SERVER_2003_R2': {'os_name': 'Microsoft Windows Server 2003 R2', 'os_major': '10', 'os_minor': '0',
                               'os_platform': 'windows', 'name': 'windows_server_2003_r2', 'os_version': '1000'},
    'WINDOWS_SERVER_2008': {'os_name': 'Microsoft Windows Server 2008', 'os_major': '10', 'os_minor': '0',
                            'os_platform': 'windows', 'name': 'windows_server_2008', 'os_version': '1000'},
    'WINDOWS_SERVER_2008_R2': {'os_name': 'Microsoft Windows Server 2008 R2', 'os_major': '10', 'os_minor': '0',
                               'os_platform': 'windows', 'name': 'windows_server_2008_r2', 'os_version': '1000'},
    'WINDOWS_SERVER_2012': {'os_name': 'Microsoft Windows Server 2012', 'os_major': '10', 'os_minor': '0',
                            'os_platform': 'windows', 'name': 'windows_server_2012', 'os_version': '1000'},
    'WINDOWS_SERVER_2012_R2': {'os_name': 'Microsoft Windows Server 2012 R2', 'os_major': '10', 'os_minor': '0',
                               'os_platform': 'windows', 'name': 'windows_server_2012_r2', 'os_version': '1000'},
    'WINDOWS_SERVER_2016': {'os_name': 'Microsoft Windows Server 2016', 'os_major': '10', 'os_minor': '0',
                            'os_platform': 'windows', 'name': 'windows_server_2016', 'os_version': '1000'},
    'WINDOWS_SERVER_2019': {'os_name': 'Microsoft Windows Server 2019', 'os_major': '10', 'os_minor': '0',
                            'os_platform': 'windows', 'name': 'windows_server_2019', 'os_version': '1000'},
    'WINDOWS_SERVER_2022_1': {'os_name': 'Microsoft Windows Server 2022', 'os_major': '10', 'os_minor': '0',
                              'os_platform': 'windows', 'name': 'windows_server_2022', 'os_version': '1000'},
    'WINDOWS_SERVER_2022_2': {'os_name': 'Microsoft Windows Server 2022', 'os_major': '10', 'os_minor': '0',
                              'os_platform': 'windows', 'name': 'windows_server', 'os_version': '1000'},
    'MAC': {'os_name': 'Mac OS X', 'os_major': '10', 'os_minor': '15', 'os_platform': 'darwin',
            'name': 'macos-catalina'},
    'MACS': {'os_name': 'Mac OS X Server', 'os_major': '5', 'os_minor': '10', 'os_platform': 'darwin',
             'name': 'macos-server'},
    'ARCH': {'os_name': 'Arch Linux', 'os_major': '', 'os_minor': '', 'os_platform': '', 'name': 'archlinux'},
    'ALAS': {'hostname': 'amz', 'architecture': 'x86_64', 'os_name': 'Amazon Linux AMI', 'os_version': '2018.03',
             'os_codename': '', 'os_major': '2018', 'os_minor': '03', 'os_patch': '', 'os_build': '',
             'os_platform': 'amzn', 'sysname': 'Linux', 'release': '4.14.97-74.72.amzn1.x86_64',
             'version': 'Wazuh v4.3.0', 'os_release': '', 'checksum': '1645433796303855540', 'os_display_version': '',
             'triaged': '0', 'reference': '0886f3023b131f5bf1ecbc33f651807114cb5a53', 'name': 'amz', 'ip': '127.0.0.1',
             'register_ip': '127.0.0.1', 'internal_key': '',
             'os_uname': 'Linux |amz |4.14.97-74.72.amzn1.x86_64 |#1 SMP Tue Feb 5 20:59:30 UTC 2019 |x86_64',
             'os_arch': 'x86_64', 'config_sum': '', 'merged_sum': '', 'manager_host': 'amz', 'node_name': 'node01',
             'date_add': '1645433793', 'last_keepalive': '253402300799', 'sync_status': 'synced',
             'connection_status': 'active', 'disconnection_time': '0'},
    'ALAS2': {'hostname': 'alas2', 'architecture': 'x86_64', 'os_name': 'Amazon Linux', 'os_version': '2',
              'os_codename': '', 'os_major': '2', 'os_minor': '', 'os_patch': '', 'os_build': '', 'os_platform': 'amzn',
              'sysname': 'Linux', 'release': '4.14.198-152.320.amzn2.x86_64', 'version': 'Wazuh v4.3.0',
              'os_release': '', 'checksum': '1645538649327530789', 'name': 'alas2', 'ip': '127.0.0.1',
              'register_ip': '127.0.0.1', 'internal_key': '',
              'os_uname': 'Linux |alas2 |4.14.198-152.320.amzn2.x86_64 |#1 SMP Wed Sep 23 23:57:28 UTC 2020 |x86_64',
              'os_arch': 'x86_64', 'config_sum': '', 'merged_sum': '', 'manager_host': 'alas2', 'node_name': 'node01',
              'date_add': '1645538646', 'last_keepalive': '253402300799', 'sync_status': 'synced',
              'connection_status': 'active'},
    'ALAS_2022': {'hostname': 'alas2022', 'architecture': 'x86_64', 'os_name': 'Amazon Linux', 'os_version': '2022',
                  'os_codename': '', 'os_major': '2022', 'os_minor': '', 'os_patch': '', 'os_build': '',
                  'os_platform': 'amzn', 'sysname': 'Linux', 'release': '5.15.29-16.111.amzn2022.x86_64',
                  'version': 'Wazuh v4.4.0', 'os_release': '', 'checksum': '1645538649327530789', 'name': 'alas2022',
                  'ip': '127.0.0.1', 'register_ip': '127.0.0.1', 'internal_key': '', 'os_arch': 'x86_64',
                  'config_sum': '', 'merged_sum': '', 'manager_host': 'alas2022',  'node_name': 'node01',
                  'date_add': '1645538646', 'last_keepalive': '253402300799',  'sync_status': 'synced',
                  'connection_status': 'active'},
    'ALAS_2023': {'hostname': 'alas2023', 'architecture': 'x86_64', 'os_name': 'Amazon Linux', 'os_version': '2023',
                  'os_codename': '', 'os_major': '2023', 'os_minor': '', 'os_patch': '', 'os_build': '',
                  'os_platform': 'amzn', 'sysname': 'Linux', 'release': '6.2.0-26.111.amzn2023.x86_64',
                  'version': 'Wazuh v4.4.0', 'os_release': '', 'checksum': '1693284466493410477', 'name': 'alas2023',
                  'ip': '127.0.0.1', 'register_ip': '127.0.0.1', 'internal_key': '', 'os_arch': 'x86_64',
                  'config_sum': '', 'merged_sum': '', 'manager_host': 'alas2023',  'node_name': 'node01',
                  'date_add': '1645538646', 'last_keepalive': '253402300799',  'sync_status': 'synced',
                  'connection_status': 'active'},
    'RHEL9': {'os_name': 'CentOS Linux', 'os_major': '9', 'os_minor': '1', 'os_platform': 'centos',
              'name': 'centos9', 'connection_status': 'active'},
    'RHEL8': {'os_name': 'CentOS Linux', 'os_major': '8', 'os_minor': '1', 'os_platform': 'centos',
              'name': 'centos8', 'connection_status': 'active'},
    'RHEL7': {'os_name': 'CentOS Linux', 'os_major': '7', 'os_minor': '1', 'os_platform': 'centos', 'os_version': '7.0',
              'name': 'centos7'},
    'RHEL6': {'os_name': 'CentOS Linux', 'os_major': '6', 'os_minor': '1', 'os_platform': 'centos', 'os_version': '6.0',
              'name': 'centos6'},
    'RHEL5': {'os_name': 'CentOS Linux', 'os_major': '5', 'os_minor': '1', 'os_platform': 'centos', 'os_version': '5.0',
              'name': 'centos5'},
    'JAMMY': {'os_name': 'Ubuntu', 'os_major': '22', 'os_minor': '04', 'os_platform': 'ubuntu',
              'name': 'Ubuntu', 'os_version': '22.04 (Jammy Jellyfish)', 'os_codename': 'jammy', 'os_arch': 'x86_64'},
    'FOCAL': {'hostname': 'focal', 'architecture': 'x86_64', 'os_name': 'Ubuntu', 'os_version': '20.04.3 LTS',
              'os_codename': 'Focal Fossa', 'os_major': '20', 'os_minor': '04', 'os_patch': '3', 'os_build': '',
              'os_platform': 'ubuntu', 'sysname': 'Linux', 'release': '5.4.0-99-generic', 'version': 'Wazuh v4.3.0',
              'os_release': '', 'checksum': '1645531600116313579', 'name': 'focal', 'ip': '127.0.0.1',
              'register_ip': '127.0.0.1', 'internal_key': '',
              'os_uname': 'Linux |focal |5.4.0-99-generic |#112-Ubuntu SMP Thu Feb 3 13:50:55 UTC 2022 |x86_64',
              'os_arch': 'x86_64', 'config_sum': '', 'merged_sum': '', 'manager_host': 'focal', 'node_name': 'node01',
              'date_add': '1645531596', 'last_keepalive': '253402300799', 'sync_status': 'synced',
              'connection_status': 'active'},
    'BIONIC': {'os_name': 'Ubuntu', 'os_major': '18', 'os_minor': '04', 'os_platform': 'ubuntu',
               'name': 'Ubuntu-bionic'},
    'XENIAL': {'os_name': 'Ubuntu', 'os_major': '16', 'os_minor': '04', 'os_platform': 'ubuntu',
               'name': 'Ubuntu-xenial'},
    'TRUSTY': {'os_name': 'Ubuntu', 'os_major': '14', 'os_minor': '04', 'os_platform': 'ubuntu',
               'name': 'Ubuntu-trusty'},
    'BOOKWORM': {'hostname': 'bookworm', 'architecture': 'x86_64', 'os_name': 'Debian GNU/Linux', 'os_version': '12',
                 'os_codename': 'bookworm', 'os_major': '12', 'os_minor': '', 'os_patch': '', 'os_build': '',
                 'os_platform': 'debian', 'sysname': 'Linux', 'release': '6.1.0-10-amd64', 'version': 'Wazuh v4.5.0',
                 'os_release': '', 'checksum': '1692739317269125720', 'name': 'bookworm', 'ip': '127.0.0.1',
                 'register_ip': '127.0.0.1', 'internal_key': '',
                 'os_uname': 'Linux |bookworm |6.1.0-10-amd64 |#1 SMP Debian 6.1.38-1 (2023-07-14) |x86_64',
                 'os_arch': 'x86_64', 'config_sum': '', 'merged_sum': '', 'manager_host': 'bookworm',
                 'node_name': 'node01', 'date_add': '1645537986', 'last_keepalive': '253402300799',
                 'sync_status': 'synced', 'connection_status': 'active'},
    'BULLSEYE': {'hostname': 'bullseye', 'architecture': 'x86_64', 'os_name': 'Debian GNU/Linux', 'os_version': '11',
                 'os_codename': 'bullseye', 'os_major': '11', 'os_minor': '', 'os_patch': '', 'os_build': '',
                 'os_platform': 'debian', 'sysname': 'Linux', 'release': '5.10.0-10-amd64', 'version': 'Wazuh v4.3.0',
                 'os_release': '', 'checksum': '1645537989645288350', 'name': 'bullseye', 'ip': '127.0.0.1',
                 'register_ip': '127.0.0.1', 'internal_key': '',
                 'os_uname': 'Linux |bullseye |5.10.0-10-amd64 |#1 SMP Debian 5.10.84-1 (2021-12-08) |x86_64',
                 'os_arch': 'x86_64', 'config_sum': '', 'merged_sum': '', 'manager_host': 'bullseye',
                 'node_name': 'node01', 'date_add': '1645537986', 'last_keepalive': '253402300799',
                 'sync_status': 'synced', 'connection_status': 'active'},
    'BUSTER': {'os_name': 'Debian GNU/Linux', 'os_major': '10', 'os_minor': '0', 'os_platform': 'debian',
               'name': 'debian10'},
    'STRETCH': {'os_name': 'Debian GNU/Linux', 'os_major': '9', 'os_minor': '0', 'os_platform': 'debian',
                'name': 'debian9'},
    'SLED11': {'hostname': 'sled', 'architecture': 'x86_64', 'os_name': 'SLED', 'os_major': '11', 'os_minor': '',
               'os_platform': 'sled', 'name': 'Desktop11', 'os_codename': 'sled'},
    'SLED12': {'hostname': 'sled', 'architecture': 'x86_64', 'os_name': 'SLED', 'os_major': '12', 'os_minor': '',
               'os_platform': 'sled', 'name': 'Desktop12', 'os_codename': 'sled'},
    'SLED15': {'hostname': 'sled', 'architecture': 'x86_64', 'os_name': 'SLED', 'os_major': '15', 'os_minor': '',
               'os_platform': 'sled', 'name': 'Desktop15', 'os_codename': 'sled'},
    'SLES11': {'hostname': 'sles', 'architecture': 'x86_64', 'os_name': 'SLES', 'os_major': '11', 'os_minor': '',
               'os_platform': 'sles', 'name': 'Server11', 'os_codename': 'sles'},
    'SLES12': {'hostname': 'sles', 'architecture': 'x86_64', 'os_name': 'SLES', 'os_major': '12', 'os_minor': '',
               'os_platform': 'sles', 'name': 'Server12', 'os_codename': 'sles'},
    'SLES15': {'hostname': 'localhost', 'architecture': 'x64', 'os_name': 'SLES', 'os_version': '15.2',
               'os_codename': '', 'os_major': '15', 'os_minor': '', 'os_patch': '', 'os_build': '',
               'os_platform': 'sles', 'sysname': 'Linux', 'release': '5.3.18-22-default', 'version': 'Wazuh v4.4.0',
               'os_release': '', 'checksum': '1652388661375945607', 'name': 'SUSE15', 'ip': '127.0.0.1',
               'register_ip': 'any', 'internal_key': '',
               'os_uname': 'Linux |localhost|5.3.18-22-default |#1 SMP Wed Jun 3 12:16:43 UTC 2020 (720aeba)|x86_64',
               'os_arch': 'x64', 'config_sum': '', 'merged_sum': '', 'manager_host': 'localhost.localdomain',
               'node_name': 'node01', 'date_add': '1652381429', 'last_keepalive': '253402300799',
               'sync_status': 'synced', 'connection_status': 'active'},
    'AlmaLinux-8': {'hostname': 'localhost', 'architecture': 'x64', 'os_name': 'AlmaLinux', 'os_version': '8',
                    'os_codename': '', 'os_major': '8', 'os_minor': '', 'os_patch': '', 'os_build': '',
                    'os_platform': 'almalinux', 'sysname': 'Linux', 'release': '5.3.18-22-default',
                    'version': 'Wazuh v4.4.0', 'os_release': '', 'checksum': '1652388661375945607',
                    'name': 'ALMALINUX8', 'ip': '127.0.0.1', 'register_ip': 'any', 'internal_key': '',
                    'os_arch': 'x64', 'config_sum': '', 'merged_sum': '', 'manager_host': 'localhost.localdomain',
                    'node_name': 'node01', 'date_add': '1652381429', 'last_keepalive': '253402300799',
                    'sync_status': 'synced', 'connection_status': 'active'}
}


def set_system(system, agent_id='000'):
    """Set custom system in global DB Agent info.

    Args:
        system (str): System to set. Available systems in SYSTEM_DATA variable.
    """
    global_db.modify_system(agent_id=agent_id, os_name=SYSTEM_DATA[system]['os_name'],
                            os_major=SYSTEM_DATA[system]['os_major'], os_minor=SYSTEM_DATA[system]['os_minor'],
                            name=SYSTEM_DATA[system]['name'])

    agent_db.update_os_info(agent_id=agent_id, os_name=SYSTEM_DATA[system]['os_name'],
                            os_major=SYSTEM_DATA[system]['os_major'], os_minor=SYSTEM_DATA[system]['os_minor'],
                            hostname=SYSTEM_DATA[system]['name'])


def create_mocked_agent(name='centos8-agent', ip='127.0.0.1', register_ip='127.0.0.1', internal_key='',
                        os_name='CentOS Linux', os_version='8.4', os_major='8', os_minor='4', os_codename='centos-8',
                        os_build='4.18.0-147.8.1.el8_1.x86_64', os_platform='#1 SMP Thu Apr 9 13:49:54 UTC 2020',
                        os_uname='x64', os_arch='x64', version='Wazuh v4.3.0', config_sum='', merged_sum='',
                        manager_host='centos-8', node_name='node01', date_add='1612942494', hostname='centos-8',
                        last_keepalive='253402300799', group='', sync_status='synced', connection_status='active',
                        client_key_secret=None, os_release='', os_patch='', release='', sysname='Linux',
                        checksum='checksum', os_display_version='', triaged='0', reference='', disconnection_time='0',
                        architecture='x64'):

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
        hostname (str): Hostname.
        last_keepalive (str): Last keep alive timestamp reported.
        group (str): Group of the agent.
        sync_status (str): Status of the syncronization.
        connection_status (str): Status of the connection.
        client_key_secret (str): Client secret key.
        os_release (str): Os release.
        os_patch (str): Os patch.
        release (str): Release.
        sysname (str): System name.
        checksum (str): Checksum.
        os_display_version (str): OS displayed version.
        triaged (str): Triaged.
        reference (str): Reference.
        disconnection_time (str): Last disconnection time.
        architecture (str): Architecture.

    Return:
        str: Agent ID.
    """

    # Get new agent_id
    last_id = global_db.get_last_agent_id()
    agent_id = int(last_id) + 1
    agent_id_str = str(agent_id).zfill(3)  # Convert from x to 00x

    client_keys.add_client_keys_entry(agent_id_str, name, ip, client_key_secret)

    # Create the new agent
    global_db.create_or_update_agent(agent_id=agent_id_str, name=name, ip=ip, register_ip=register_ip,
                                     internal_key=internal_key, os_name=os_name, os_version=os_version,
                                     os_major=os_major, os_minor=os_minor, os_codename=os_codename, os_build=os_build,
                                     os_platform=os_platform, os_uname=os_uname, os_arch=os_arch, version=version,
                                     config_sum=config_sum, merged_sum=merged_sum, manager_host=manager_host,
                                     node_name=node_name, date_add=date_add, last_keepalive=last_keepalive, group=group,
                                     sync_status=sync_status, connection_status=connection_status,
                                     disconnection_time=disconnection_time)

    # Restart Wazuh-DB before creating new DB
    control_service('restart', daemon='wazuh-db')

    # sleep is needed since, without it, the agent database creation may fail
    sleep(3)

    # Add or update os_info related to the new created agent
    agent_db.update_os_info(agent_id=agent_id_str, hostname=hostname, architecture=os_arch, os_name=os_name,
                            os_version=os_version, os_codename=os_codename, os_major=os_major, os_minor=os_minor,
                            os_patch=os_patch, os_build=os_build, os_platform=os_platform, sysname=sysname,
                            release=release, version=version, os_release=os_release, checksum=checksum,
                            os_display_version=os_display_version, triaged=triaged, reference=reference)

    return agent_id_str


def delete_mocked_agent(agent_id):
    """Delete a mocked agent removing it from the global db, client keys and db file.

    Args:
        agent_id (str): Agent ID.
    """
    # Remove from global db
    global_db.delete_agent(agent_id)

    # Remove agent id DB file if exists
    remove_file(os.path.join(wazuh_testing.QUEUE_DB_PATH, f"{agent_id}.db"))

    # Remove entry from client keys
    client_keys.delete_client_keys_entry(agent_id)


def insert_mocked_packages(agent_id='000', num_packages=10):
    """Insert a specific number of mocked packages in the agent DB (package_1, package2 ...).

    Args:
        agent_id (str): Agent ID.
        num_packages (int): Number of packages to generate.

    Returns:
        list(str): List of package names.
    """
    package_names = [f"package_{number}" for number in range(1, num_packages + 1)]

    for package_name in package_names:
        agent_db.insert_package(agent_id=agent_id, name=package_name, version='1.0.0')

    return package_names


def delete_mocked_packages(agent_id='000'):
    """Delete the mocked packages in the agent DB.

    Args:
        agent_id (str): Agent ID.
    """
    package_names = [f"package_{number}" for number in range(1, 11)]

    for package_name in package_names:
        agent_db.delete_package(package=package_name, agent_id=agent_id)


def delete_all_mocked_agents(name='mocked_agent'):
    """Delete all mocked agents by name.

    Args:
        name (str): Name of mocked agents to delete.
    """
    for agent_id in global_db.get_agent_ids(name):
        delete_mocked_agent(agent_id)


def delete_all_agents():
    """Delete all mocked agents except id 000."""
    for agent_id in global_db.get_all_agent_ids():
        delete_mocked_agent(agent_id)
