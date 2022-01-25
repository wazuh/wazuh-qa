from wazuh_testing.db_interface import query_wdb


def modify_system(os_name='CentOS Linux', os_major='7', name='centos7', agent_id='000', os_minor='1', os_arch='x86_64',
                  os_version='7.1', os_platform='centos', version='4.0'):
    """Modify the manager or agent system.

    Args:
        os_name (str): OS complete name.
        os_major (str): OS major version.
        name (str): Os name.
        agent_id (str): Agent ID.
        os_minor (str): OS minor version.
        os_arch (str): Host architecture.
        os_version (str): OS version.
        os_platform (str): Os platform e.g (centos, ubuntu, ...).
        version (str): OS version.
    """
    query_string = f"global sql update AGENT set OS_NAME='{os_name}', OS_VERSION='{os_version}', " \
                   f"OS_MAJOR='{os_major}', OS_MINOR='{os_minor}', OS_ARCH='{os_arch}', NAME='{name}', " \
                   f"OS_PLATFORM='{os_platform}', VERSION='{version}' WHERE id='{int(agent_id)}'"
    query_wdb(query_string)


def create_or_update_agent(agent_id='001', name='centos8-agent', ip='127.0.0.1', register_ip='127.0.0.1',
                           internal_key='', os_name='CentOS Linux', os_version='8.4', os_major='8', os_minor='4',
                           os_codename='centos-8', os_build='4.18.0-147.8.1.el8_1.x86_64',
                           os_platform='#1 SMP Thu Apr 9 13:49:54 UTC 2020', os_uname='x86_64', os_arch='x86_64',
                           version='4.2', config_sum='', merged_sum='', manager_host='centos-8', node_name='node01',
                           date_add='1612942494', last_keepalive='253402300799', group='', sync_status='synced',
                           connection_status='active'):
    """Create an agent or update its info if it already exists (checking agent_id).

    Args:
        agent_id (str): Agent ID.
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
    """

    query = 'global sql INSERT OR REPLACE INTO AGENT  (id, name, ip, register_ip, internal_key, os_name, os_version, ' \
            'os_major, os_minor, os_codename, os_build, os_platform, os_uname, os_arch, version, config_sum, ' \
            'merged_sum, manager_host, node_name, date_add, last_keepalive, "group", sync_status, connection_status) ' \
            f"VALUES  ('{agent_id}', '{name}', '{ip}', '{register_ip}', '{internal_key}', '{os_name}', " \
            f"'{os_version}', '{os_major}', '{os_minor}', '{os_codename}', '{os_build}', '{os_platform}', " \
            f"'{os_uname}', '{os_arch}', '{version}', '{config_sum}', '{merged_sum}', '{manager_host}', " \
            f"'{node_name}', '{date_add}', '{last_keepalive}', '{group}', '{sync_status}', '{connection_status}')"
    query_wdb(query)


def get_last_agent_id():
    """Get the last agent ID registered in the global DB.

    Returns:
        str: Agent ID.
    """
    last_id = query_wdb('global sql SELECT id FROM agent order by id desc limit 1')
    return last_id[0]['id']


def delete_agent(agent_id):
    """Delete an agent from the global.db

    Args:
        agent_id (str): Agent ID.
    """
    query_wdb(f"global sql DELETE FROM agent where id={int(agent_id)}")
