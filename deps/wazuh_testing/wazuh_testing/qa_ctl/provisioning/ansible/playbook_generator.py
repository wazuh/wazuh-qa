import os
from tempfile import gettempdir

from wazuh_testing.qa_ctl.provisioning.ansible.ansible_playbook import AnsiblePlaybook
from wazuh_testing.qa_ctl.provisioning.ansible.ansible_task import AnsibleTask
from wazuh_testing.tools.time import get_current_timestamp

OS_SYSTEM = ['centos', 'ubuntu']
OS_PLATFORM = ['linux', 'windows']
PACKAGE_MANAGER = {'centos': 'RPM', 'ubuntu': 'DEB'}
PLAYBOOSK_PATH = os.path.join(gettempdir(), 'wazuh_playbooks')


def validate_playbook_parameters(parameters):
    """Validate if the required parameters to build the playbook are specified.

    Raises:
        ValueError: If a required playbook parameter has not been specified.
    """
    required_parameters = ['tasks_list']

    for required_parameter in required_parameters:
        if required_parameter not in parameters.keys():
            raise ValueError(f"{required_parameter} is a required parameter to generate the playbook.")


def install_wazuh(wazuh_target, package_name, package_url, package_destination, os_system, os_platform, manager_ip=None,
                  playbook_parameters=None):
    """Generate the playbook to install Wazuh.

    Args:
        wazuh_target (str): Wazuh target [manager or agent].
        package_name (str): Name of the package to be installed.
        package_url (str): URL of the package to be installed.
        package_destination (str): Destination folder where the package will be downloaded.
        os_system (str): Operating system where the test will be launched.
        os_platform (str): Platform where the package will be installed.
        playbook_parameters (dict): Extra non-tasks playbook parameters.
        manager_ip (str): IP of the manager, to be configured if the target is an agent.

    Raises:
        ValueError: If os_system or os_platform has not an expected value.

    Returns:
        str: Playbook file path generated.
    """
    tasks = []
    _os_system = _clean_os_system(os_system)

    if os_platform == 'linux':
        if PACKAGE_MANAGER[_os_system] == 'RPM':
            tasks = _install_wazuh_rpm(package_name, package_url, package_destination, wazuh_target, manager_ip)
        elif PACKAGE_MANAGER[_os_system] == 'DEB':
            tasks = _install_wazuh_deb(package_name, package_url, package_destination, wazuh_target, manager_ip)
        else:
            raise ValueError(f"{os_system} is not supported in PlaybookGenerator")
    else:
        raise ValueError(f"{os_platform} is not supported in PlaybookGenerator")

    parameters = dict(**playbook_parameters) if playbook_parameters else {}
    parameters.update({'name': 'install_wazuh', 'tasks_list': tasks})

    return _build_playbook(parameters)


def upgrade_wazuh(package_name, package_url, package_destination, os_system, os_platform, playbook_parameters=None):
    """Generate the playbook to upgrade Wazuh.

    Args:
        package_name (str): Name of the package to be installed.
        package_url (str): URL of the package to be installed.
        package_destination (str): Destination folder where the package will be downloaded.
        os_system (str): Operating system where the test will be launched.
        os_platform (str): Platform where the package will be installed.
        playbook_parameters (dict): Extra non-tasks playbook parameters.

    Raises:
       ValueError: If os_system or os_platform has not an expected value.

    Returns:
        str: Playbook file path generated.
    """
    tasks = []
    _os_system = _clean_os_system(os_system)

    if os_platform == 'linux':
        if PACKAGE_MANAGER[_os_system] == 'RPM':
            tasks = _upgrade_wazuh_rpm(package_name, package_url, package_destination)
        elif PACKAGE_MANAGER[_os_system] == 'DEB':
            tasks = _upgrade_wazuh_deb(package_name, package_url, package_destination)
        else:
            raise ValueError(f"{os_system} is not supported in PlaybookGenerator")
    else:
        raise ValueError(f"{os_platform} is not supported in PlaybookGenerator")

    parameters = dict(**playbook_parameters) if playbook_parameters else {}
    parameters.update({'name': 'upgrade_wazuh', 'tasks_list': tasks})

    return _build_playbook(parameters)


def uninstall_wazuh(wazuh_target, os_system, os_platform, playbook_parameters=None):
    """Generate the playbook to uninstall Wazuh.

    Args:
        wazuh_target (str): Wazuh target [manager or agent].
        os_system (str): Operating system where the test will be launched.
        os_platform (str): Platform where the package will be installed.
        playbook_parameters (dict): Extra non-tasks playbook parameters.

    Raises:
        ValueError: If os_system or os_platform has not an expected value.

    Returns:
        str: Playbook file path generated.
    """
    tasks = []
    _os_system = _clean_os_system(os_system)

    if os_platform == 'linux':
        if PACKAGE_MANAGER[_os_system] == 'RPM':
            tasks = _uninstall_wazuh_rpm(wazuh_target)
        elif PACKAGE_MANAGER[_os_system] == 'DEB':
            tasks = _uninstall_wazuh_deb(wazuh_target)
        else:
            raise ValueError(f"{os_system} is not supported in PlaybookGenerator")
    else:
        raise ValueError(f"{os_platform} is not supported in PlaybookGenerator")

    parameters = dict(**playbook_parameters) if playbook_parameters else {}
    parameters.update({'name': 'uninstall_wazuh', 'tasks_list': tasks})

    return _build_playbook(parameters)


def restart_wazuh(wazuh_target, playbook_parameters=None):
    """Generate a playbook to restart wazuh.

    Args:
        wazuh_target (str): Wazuh target [manager or agent].
        playbook_parameters (dict): Extra non-tasks playbook parameters.

    Returns:
        str: Playbook file path generated.
    """
    tasks = _restart_wazuh_systemd_service(wazuh_target)

    parameters = dict(**playbook_parameters) if playbook_parameters else {}
    parameters.update({'name': f'restart_wazuh_{wazuh_target}', 'tasks_list': tasks})

    return _build_playbook(parameters)


def start_wazuh(wazuh_target, playbook_parameters=None):
    """Generate a playbook to start wazuh.

    Args:
        wazuh_target (str): Wazuh target [manager or agent].
        playbook_parameters (dict): Extra non-tasks playbook parameters.

    Returns:
        str: Playbook file path generated.
    """
    tasks = []
    if 'manager' in wazuh_target:
        tasks.extend(_start_wazuh_manager_systemd_service())
    if 'agent' in wazuh_target:
        tasks.extend(_start_wazuh_agent_systemd_service())

    parameters = dict(**playbook_parameters) if playbook_parameters else {}
    parameters.update({'name': f'start_wazuh_{wazuh_target}', 'tasks_list': tasks})

    return _build_playbook(parameters)


def stop_wazuh(wazuh_target, playbook_parameters=None):
    """Generate a playbook to stop wazuh.

    Args:
        wazuh_target (str): Wazuh target [manager or agent].
        playbook_parameters (dict): Extra non-tasks playbook parameters.

    Returns:
        str: Playbook file path generated.
    """
    tasks = []

    if 'manager' in wazuh_target:
        tasks.extend(_stop_wazuh_manager_systemd_service())
    if 'agent' in wazuh_target:
        tasks.extend(_stop_wazuh_agent_systemd_service())

    parameters = dict(**playbook_parameters) if playbook_parameters else {}
    parameters.update({'name': f'stop_wazuh_{wazuh_target}', 'tasks_list': tasks})

    return _build_playbook(parameters)


def configure_agent_disconnection_time(time, playbook_parameters=None):
    """Generate a playbook to configure agent_disconnection_time.

    Args:
        time (str): Time after which the manager considers an agent as disconnected since its last keepalive. A
                    positive number that should end with a character indicating a time unit, such as: s (seconds),
                    m (minutes), h (hours), d (days). The minimum allowed is 1s.
        playbook_parameters (dict): Extra non-tasks playbook parameters.

    Returns:
        str: Playbook file path generated.
    """
    tasks = _configure_agent_disconnection_time(time)

    parameters = dict(**playbook_parameters) if playbook_parameters else {}
    parameters.update({'name': f'configure_agent_disconnection_time', 'tasks_list': tasks})

    return _build_playbook(parameters)


def configure_time_reconnect(time, playbook_parameters=None):
    """Generate a playbook to configure time-reconnect.

    Args:
        time (str): Specifies the time in seconds before a reconnection is attempted.
        playbook_parameters (dict): Extra non-tasks playbook parameters.

    Returns:
        str: Playbook file path generated.
    """
    tasks = _configure_time_reconnect(time)

    parameters = dict(**playbook_parameters) if playbook_parameters else {}
    parameters.update({'name': f'configure_time_reconnect', 'tasks_list': tasks})

    return _build_playbook(parameters)


def configure_manager_ip(manager_ip, playbook_parameters=None):
    """Generate a playbook to configure manager ip in the agent.

    Args:
        manager_ip (str): IP of the manager node.
        playbook_parameters (dict): Extra non-tasks playbook parameters.

    Returns:
        str: Playbook file path generated.
    """
    tasks = _configure_manager_ip(manager_ip)

    parameters = dict(**playbook_parameters) if playbook_parameters else {}
    parameters.update({'name': f'configure_manager_ip', 'tasks_list': tasks})

    return _build_playbook(parameters)


def run_linux_commands(commands, playbook_parameters=None):
    """Generate a playbook to run linux commands.

    Args:
        commands (list(str)): Commands to run with the playbook. [command1, command2, ...]
        playbook_parameters (dict): Extra non-tasks playbook parameters.

    Returns:
        str: Playbook file path generated.
    """
    tasks = _run_linux_commands(commands)

    parameters = dict(**playbook_parameters) if playbook_parameters else {}
    parameters.update({'name': 'run_linux_commands', 'tasks_list': tasks})

    return _build_playbook(parameters)


def download_files(files_data, playbook_parameters=None):
    """Generate a playbook to download files.

    Args:
        files_data (list(dict)): URL and download destination info. [{url: destination}, ...]
        playbook_parameters (dict): Extra non-tasks playbook parameters.

    Returns:
        str: Playbook file path generated.
    """
    tasks = _download_files(files_data)

    parameters = dict(**playbook_parameters) if playbook_parameters else {}
    parameters.update({'name': 'download_files', 'tasks_list': tasks})

    return _build_playbook(parameters)


def fetch_files(files_data, playbook_parameters=None):
    """Generate a playbook to fetch files.

    Args:
        files_data (list(dict)): Source and destination data. [{remote_src: local_destination}, ...]
        playbook_parameters (dict): Extra non-tasks playbook parameters.

    Returns:
        str: Playbook file path generated.
    """
    tasks = _fetch_files(files_data)

    parameters = dict(**playbook_parameters) if playbook_parameters else {}
    parameters.update({'name': 'fetch_files', 'tasks_list': tasks})

    return _build_playbook(parameters)


def copy_files(files_data, playbook_parameters=None):
    """Generate a playbook to copy files from the control machine to a managed node.

    Args:
        files_data (list(dict)): Local source and remote destination data [{local_source: node_destination},...]
        playbook_parameters (dict): Extra non-tasks playbook parameters.

    Returns:
        str: Playbook file path generated.
    """
    tasks = _copy_files(files_data)

    parameters = dict(**playbook_parameters) if playbook_parameters else {}
    parameters.update({'name': 'copy_files', 'tasks_list': tasks})

    return _build_playbook(parameters)


def toggle_agent_enrollment(alternator, playbook_parameters=None):
    tasks = _toggle_agent_enrollment(alternator)

    parameters = dict(**playbook_parameters) if playbook_parameters else {}
    parameters.update({'name': 'toggle_agent_enrollment', 'tasks_list': tasks})

    return _build_playbook(parameters)


def delete_files(files_path, playbook_parameters=None):
    """Generate a playbook to delete files.

    Args:
        files_path (list(str)): List of files path to delete. [file_path1, file_path2, ...]
        playbook_parameters (dict): Extra non-tasks playbook parameters.

    Returns:
        str: Playbook file path generated.
    """
    tasks = _delete_files(files_path)

    parameters = dict(**playbook_parameters) if playbook_parameters else {}
    parameters.update({'name': 'delete_files', 'tasks_list': tasks})

    return _build_playbook(parameters)


def wait_seconds(num_seconds, playbook_parameters=None):
    """Generate a playbook to wait for the indicated time.

    Args:
        num_seconds (int): Number of seconds to wait.
        playbook_parameters (dict): Extra non-tasks playbook parameters.

    Returns:
        str: Playbook file path generated.
    """
    tasks = _wait_seconds(num_seconds)

    parameters = dict(**playbook_parameters) if playbook_parameters else {}
    parameters.update({'name': 'wait_seconds', 'tasks_list': tasks})

    return _build_playbook(parameters)


# -------------------------------------------------------------------------------------------------------------------- #
#                                        BUILDER AND UTILS FUNCTION                                                    #
# -------------------------------------------------------------------------------------------------------------------- #


def _build_playbook(parameters):
    """Generate the playbook with the specific parameters.

    Args:
        parameters (dict): Parameters of the playbook to be generated.

    Returns:
        str: Playbook file path generated.
    """
    # Validate if the required parameters to build the playbook are specified.
    validate_playbook_parameters(parameters)

    current_timestamp = str(get_current_timestamp()).replace('.', '_')
    playbook_file_path = os.path.join(PLAYBOOSK_PATH,
                                      f"{parameters['name']}_{current_timestamp}.yaml")

    playbook_parameters = dict(**parameters) if parameters else {}
    playbook_parameters.update({'playbook_file_path': playbook_file_path, 'generate_file': True})

    playbook = AnsiblePlaybook(**playbook_parameters)

    return playbook.playbook_file_path


def _clean_os_system(os_system):
    """Clean the operating system version, returning only the system.

    Args:
        os_system (str): Operating system.

    Raises:
        ValueError: If the os_system has an invalid value.

    Returns:
        str: Operating system without the version.
    """
    if 'centos' in os_system:
        return 'centos'
    elif 'ubuntu' in os_system:
        return 'ubuntu'
    else:
        raise ValueError(f"{os_system} is not allowed in PlaybookGenerator module")


# -------------------------------------------------------------------------------------------------------------------- #
#                                        PLAYBOOK TASKS DEFINITION                                                     #
# -------------------------------------------------------------------------------------------------------------------- #


def _download_wazuh_package(package_url, package_destination):
    """Ansible tasks to download a package.

    Args:
        package_url (str): URL of the package to be downloaded.
        package_destination (str): Destination where the package will be stored

    Returns:
        list(AnsibleTask): Ansible tasks to download the wazuh package.
    """
    return [
        AnsibleTask({
            'name': 'Download Wazuh package',
            'get_url': {
                'url': package_url,
                'dest': package_destination,
                'mode': '0755'
            },
            'register': 'download_package',
            'retries': 6,
            'delay': 10,
            'until': 'download_package is success'
        })
    ]


def _restart_wazuh_systemd_service(wazuh_target):
    """Ansible tasks to restart the wazuh-manager service with systemd.

    Args:
        wazuh_target (str): Wazuh target [manager or agent].

    Returns:
        list(AnsibleTask): Ansible tasks.
    """
    tasks = []

    if 'manager' in wazuh_target:
        tasks.extend(_stop_wazuh_manager_systemd_service())
        tasks.extend(_start_wazuh_manager_systemd_service())
    if 'agent' in wazuh_target:
        tasks.extend(_stop_wazuh_agent_systemd_service())
        tasks.extend(_start_wazuh_agent_systemd_service())

    return tasks


def _start_wazuh_manager_systemd_service():
    """Ansible tasks to start the wazuh-manager service with systemd.

    Returns:
        list(AnsibleTask): Ansible tasks.
    """
    return [
        AnsibleTask({
            'name': 'Start Wazuh Manager service with systemd',
            'become': True,
            'ansible.builtin.systemd': {
              'state': 'started',
              'name': 'wazuh-manager'
            }
        })
    ]


def _start_wazuh_agent_systemd_service():
    """Ansible tasks to start the wazuh-agent service with systemd.

    Returns:
        list(AnsibleTask): Ansible tasks.
    """
    return [
        AnsibleTask({
            'name': 'Start Wazuh Agent service with systemd',
            'become': True,
            'ansible.builtin.systemd': {
              'state': 'started',
              'name': 'wazuh-agent'
            }
        })
    ]


def _stop_wazuh_manager_systemd_service():
    """Ansible tasks to stop the wazuh-manager service with systemd.

    Returns:
        list(AnsibleTask): Ansible tasks.
    """
    return [
        AnsibleTask({
            'name': 'Stop Wazuh Manager service with systemd',
            'become': True,
            'ansible.builtin.systemd': {
              'state': 'stopped',
              'name': 'wazuh-manager'
            }
        })
    ]


def _stop_wazuh_agent_systemd_service():
    """Ansible tasks to stop the wazuh-agent service with systemd.

    Returns:
       list(AnsibleTask): Ansible tasks.
    """
    return [
        AnsibleTask({
            'name': 'Stop Wazuh Agent service with systemd',
            'become': True,
            'ansible.builtin.systemd': {
              'state': 'stopped',
              'name': 'wazuh-agent'
            }
        })
    ]


def _start_wazuh_control_service(wazuh_target):
    """Ansible tasks to start the wazuh-agent or wazuh-manager using wazuh-control.

    Args:
        wazuh_target (str): Wazuh target [manager or agent].

    Returns:
       list(AnsibleTask): Ansible tasks.
    """
    return [
        AnsibleTask({
            'name': f"Start Wazuh {wazuh_target} service with systemd",
            'become': True,
            'shell': '/var/ossec/bin/wazuh-control start',
        })
    ]


def _stop_wazuh_control_service(wazuh_target):
    """Ansible tasks to stop the wazuh-agent or wazuh-manager using wazuh-control.

    Args:
        wazuh_target (str): Wazuh target [manager or agent].

    Returns:
        list(AnsibleTask): Ansible tasks.
    """
    return [
        AnsibleTask({
            'name': f"Stop Wazuh {wazuh_target} service with systemd",
            'become': True,
            'shell': '/var/ossec/bin/wazuh-control stop',
        })
    ]


def _install_wazuh_rpm(package_name, package_url, package_destination, wazuh_target, manager_ip):
    """Ansible tasks to install a wazuh RPM package.

    Args:
        package_name (str): Name of the package to be installed.
        package_url (str): URL of the package to be installed.
        package_destination (str): Destination folder where the package will be downloaded.
        wazuh_target (str): Wazuh target [manager or agent].
        manager_ip (str): IP of the manager, to be configured if the target is an agent.

    Returns:
        list(AnsibleTask): Ansible tasks.
    """
    tasks = []

    tasks.extend(_download_wazuh_package(package_url, package_destination))
    tasks.append(
        AnsibleTask({
            'name': 'Install Wazuh RPM package',
            'become': True,
            'shell': f"yum install -y {package_name}",
            'args': {
                'chdir': package_destination
            },
            'register': 'rpm_install',
            'retries': 6,
            'delay': 10,
            'until': 'rpm_install is success',
        })
    )
    if 'manager' in wazuh_target:
        tasks.extend(_start_wazuh_manager_systemd_service())
    elif 'agent' in wazuh_target:
        tasks.extend(_configure_manager_ip(manager_ip))
        tasks.extend(_start_wazuh_agent_systemd_service())

    return tasks


def _install_wazuh_deb(package_name, package_url, package_destination, wazuh_target, manager_ip):
    """Ansible tasks to install a wazuh DEB package.

    Args:
        package_name (str): Name of the package to be installed.
        package_url (str): URL of the package to be installed.
        package_destination (str): Destination folder where the package will be downloaded.
        wazuh_target (str): Wazuh target [manager or agent].
        manager_ip (str): IP of the manager, to be configured if the target is an agent.

    Returns:
        list(AnsibleTask): Ansible tasks.
    """
    tasks = []

    tasks.extend(_download_wazuh_package(package_url, package_destination))
    tasks.append(
        AnsibleTask({
            'name': 'Install Wazuh DEB package',
            'become': True,
            'apt': {'deb': f"{package_destination}/{package_name}"},
            'register': 'deb_install',
            'retries': 6,
            'delay': 10,
            'until': 'deb_install is success',
        })
    )
    if 'manager' in wazuh_target:
        tasks.extend(_start_wazuh_manager_systemd_service())
    elif 'agent' in wazuh_target:
        tasks.extend(_configure_manager_ip(manager_ip))
        tasks.extend(_start_wazuh_agent_systemd_service())

    return tasks


def _upgrade_wazuh_rpm(package_name, package_url, package_destination):
    """Ansible tasks to upgrade a wazuh RPM package.

    Args:
        package_name (str): Name of the package to be installed.
        package_url (str): URL of the package to be installed.
        package_destination (str): Destination folder where the package will be downloaded.

    Returns:
       list(AnsibleTask): Ansible tasks.
    """
    tasks = []

    tasks.extend(_download_wazuh_package(package_url, package_destination))

    tasks.append(
        AnsibleTask({
            'name': 'Upgrade wazuh RPM package',
            'become': True,
            'shell': f"yum install -y {package_name}",
            'args': {
                'chdir': package_destination
            },
            'register': 'rpm_upgrade',
            'retries': 6,
            'delay': 10,
            'until': 'rpm_upgrade is success',
        })
    )

    return tasks


def _upgrade_wazuh_deb(package_name, package_url, package_destination):
    """Ansible tasks to upgrade a wazuh DEB package.

    Args:
        package_name (str): Name of the package to be installed.
        package_url (str): URL of the package to be installed.
        package_destination (str): Destination folder where the package will be downloaded.

    Returns:
        list(AnsibleTask): Ansible tasks.
    """
    tasks = []

    tasks.extend(_download_wazuh_package(package_url, package_destination))

    tasks.append(
        AnsibleTask({
            'name': 'Upgrade wazuh DEB package',
            'become': True,
            'apt': {
                'deb': f"{package_destination}/{package_name}",
            },
            'register': 'deb_upgrade',
            'retries': 6,
            'delay': 10,
            'until': 'deb_upgrade is success',
        })
    )

    return tasks


def _uninstall_wazuh_rpm(wazuh_target):
    """Ansible tasks to uninstall a wazuh RPM package.

    Args:
        wazuh_target (str): Wazuh target [manager or agent].

    Returns:
        list(AnsibleTask): Ansible tasks.
    """
    tasks = [
        AnsibleTask({
            'name': 'Uninstall wazuh RPM package',
            'become': True,
            'shell': f"yum remove -y wazuh-{wazuh_target}",
        })
    ]

    tasks.extend(_delete_files(['/var/ossec']))

    return tasks


def _uninstall_wazuh_deb(wazuh_target):
    """Ansible tasks to uninstall a wazuh DEB package.

    Args:
        wazuh_target (str): Wazuh target [manager or agent].

    Returns:
        list(AnsibleTask): Ansible tasks.
    """
    return [
        AnsibleTask({
            'name': 'Uninstall wazuh DEB package',
            'become': True,
            'apt': {
                'name': f"wazuh-{wazuh_target}",
                'state': 'absent',
                'purge': True
            }
        })
    ]


def _toggle_agent_enrollment(alternator):

    return [
        AnsibleTask({
            'name': 'Insert a block of multi-line text',
            'blockinfile': {
                'path': '/var/ossec/etc/ossec.conf',
                'insertafter': '</client>',
                'block': f"\n  <client>\n    <enrollment>\n        <enabled>"
                         f"{'yes' if alternator else 'no'}</enabled>\n    </enrollment>\n"
                         f"  </client>\n",
                'state': 'present'
            }
        })
    ]


def _configure_agent_disconnection_time(time):

    return [
        AnsibleTask({
            'name': 'Configurate the IP of the manager in Agent',
            'lineinfile': {
                'path': '/var/ossec/etc/ossec.conf',
                'regexp': '<agents_disconnection_time>.*</agents_disconnection_time>',
                'line': f'    <agents_disconnection_time>{time}</agents_disconnection_time>',
                'state': 'present'
            }
        })
    ]


def _configure_time_reconnect(time):

    return [
        AnsibleTask({
            'name': 'Configurate the time-reconnect option',
            'lineinfile': {
                'path': '/var/ossec/etc/ossec.conf',
                'regexp': '<time-reconnect>.*</time-reconnect>',
                'line': f'    <time-reconnect>{time}</time-reconnect>',
                'state': 'present'
            }
        })
    ]


def _configure_manager_ip(manager_ip):
    """Ansible tasks to configurate the manager ip in the agent endpoint

        Args:
            manager_ip (str): IP of the manager

        Returns:
            list(AnsibleTask): Ansible tasks.
    """

    return [
        AnsibleTask({
            'name': 'Configurate the IP of the manager in Agent',
            'become': True,
            'lineinfile': {
                'path': '/var/ossec/etc/ossec.conf',
                'regexp': '<address>.*</address>',
                'line': f'      <address>{manager_ip}</address>',
                'state': 'present'
            }
        })
    ]


def _run_linux_commands(commands):
    """Ansible tasks to run linux commands.

    Args:
        commands (list(str)): Commands to run with the playbook. [command1, command2, ...]

    Returns:
        list(AnsibleTask): Ansible tasks.
    """
    return [
       AnsibleTask({
           # command(str) is sliced to avoid adding the character '\n' after position 60
           'name': f"Run Command {command[:60]}",
           'shell': command
        }) for command in commands
    ]


def _download_files(files_data):
    """Ansible tasks to download files.

    Args:
        files_data (list(dict)): URL and download destination info. [{url: destination}, ...]

    Returns:
       list(AnsibleTask): Ansible tasks.
    """
    return [
       AnsibleTask({
            'name': f"Download_file {file_url}",
            'get_url': {
                'url': file_url,
                'dest': file_destination,
                'mode': '0755'
            },
            'register': 'download_file',
            'retries': 3,
            'delay': 10,
            'until': 'download_file is success'
        }) for file_url, file_destination in files_data.items()
    ]


def _fetch_files(files_data):
    """Ansible tasks to fetch remote files to a local path.

    Args:
        files_data (list(dict)): Source and destination data. [{remote_src: local_destination}, ...]

    Returns:
        list(AnsibleTask): Ansible tasks.
    """
    return [
       AnsibleTask({
            'name': f"Fetch {remote_file_path} from remote path to {local_file_path} local path",
            'fetch': {
                'src': remote_file_path,
                'dest': local_file_path,
                'flat': 'yes'
            }
        }) for remote_file_path, local_file_path in files_data.items()
    ]


def _copy_files(files_data):
    """Ansible tasks to copy files into a managed node

    Args:
        files_data (list(dict)): Local source and remote destination data [{local_source: node_destination},...]

    Returns:
        list(AnsibleTask): Ansible tasks.
    """
    return [
        # ':10' added to prevent the \n character from being added
        AnsibleTask({
            'name': f"Copy {local_file_path[:10] + '...' if len(local_file_path) > 10 else local_file_path} from local "
                    f"path to"
                    f" {remote_file_path[:10] + '...' if len(remote_file_path) > 10 else remote_file_path} remote path",
            'copy': {
                'src': local_file_path,
                'dest': remote_file_path
            }
        }) for local_file_path, remote_file_path in files_data.items()
    ]


def _delete_files(files_path):
    """Ansible tasks to delete files.

    Args:
        files_path (list(str)): List of files path to delete. [file_path1, file_path2, ...]

    Returns:
        list(AnsibleTask): Ansible tasks.
    """
    return [
        AnsibleTask({
            'name': f"Delete {item}",
            'become': True,
            'file': {
                'state': 'absent',
                'path': item
            }
        }) for item in files_path
    ]


def _wait_seconds(num_seconds):
    """Ansible tasks to wait for the indicated time.

    Args:
        num_seconds (int): Number of seconds to wait.

    Returns:
        list(AnsibleTask): Ansible tasks.
    """
    return [
        AnsibleTask({
            'name': f"Wait {num_seconds} seconds",
            'pause': {
                'seconds': num_seconds,
            }
        })
    ]
