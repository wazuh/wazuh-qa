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
        ValueError: If a script parameters has an invalid value.
    """
    required_parameters = ['tasks_list']

    for required_parameter in required_parameters:
        if required_parameter not in parameters.keys():
            raise ValueError(f"{required_parameter} is a required parameter to generate the playbook.")


def install_wazuh(wazuh_target, package_name, package_url, package_destination, os_system, os_platform,
                  playbook_parameters=None):
    """Generate the necessary playbooks to install Wazuh.

    Args:
        wazuh_target (str): Wazuh target [manager or agent].
        package_name (str): Name of the package to be installed.
        package_url (str): URL of the package to be installed.
        package_destination (str): Destination folder where the package will be downloaded.
        os_system (str): Operating system where the test will be launched.
        os_platform (str): Platform where the package will be installed [Centos 7, Centos 8, Ubuntu].
        playbook_parameters (str): Parameters of the playbook to be generated.

    Raises:
        ValueError: If a script parameters has an invalid value.

    Returns:
        str: Playbook file path generated.
    """
    tasks = []
    _os_system = _clean_os_system(os_system)

    if os_platform == 'linux':
        if PACKAGE_MANAGER[_os_system] == 'RPM':
            tasks = _install_wazuh_rpm(package_name, package_url, package_destination, wazuh_target)
        elif PACKAGE_MANAGER[_os_system] == 'DEB':
            tasks = _install_wazuh_deb(package_name, package_url, package_destination, wazuh_target)
        else:
            raise ValueError(f"{os_system} is not supported in PlaybookGenerator")
    else:
        raise ValueError(f"{os_platform} is not supported in PlaybookGenerator")

    parameters = dict(**playbook_parameters) if playbook_parameters else {}
    parameters.update({'name': 'install_wazuh', 'tasks_list': tasks})

    return _build_playbook(parameters)


def upgrade_wazuh(package_name, package_url, package_destination, os_system, os_platform, playbook_parameters=None):
    """Generate the necessary playbooks to upgrade Wazuh.

    Args:
        package_name (str): Name of the package to be installed.
        package_url (str): URL of the package to be installed.
        package_destination (str): Destination folder where the package will be downloaded.
        os_system (str): Operating system where the test will be launched.
        os_platform (str): Platform where the package will be installed [Centos 7, Centos 8, Ubuntu].
        playbook_parameters (str): Parameters of the playbook to be generated.

    Raises:
        ValueError: If a script parameters has an invalid value.

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
    """Generate the necessary playbooks to uninstall Wazuh.

    Args:
        wazuh_target (str): Wazuh target [manager or agent].
        os_system (str): Operating system where the test will be launched.
        os_platform (str): Platform where the package will be installed [Centos 7, Centos 8, Ubuntu].
        playbook_parameters (str): Parameters of the playbook to be generated.

    Raises:
        ValueError: If a script parameters has an invalid value.

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


def run_linux_commands(commands, playbook_parameters=None):
    """Generate a playbook to run a linux command.

    Args:
        command (str): Command to be run in the playbook.
        playbook_parameters (str): Parameters of the playbook.

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
        files_data (dict): File information about destination and url to generate the playbook.
        playbook_parameters (str): Parameters of the playbook.

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
        files_data (dict): File information about destination and url to generate the playbook.
        playbook_parameters (str): Parameters of the playbook.

    Returns:
        str: Playbook file path generated.
    """
    tasks = _fetch_files(files_data)

    parameters = dict(**playbook_parameters) if playbook_parameters else {}
    parameters.update({'name': 'fetch_files', 'tasks_list': tasks})

    return _build_playbook(parameters)


def delete_files(files_path, playbook_parameters=None):
    """Generate a playbook to delete files.

    Args:
        files_path (dict): Paths of the file to generate the playbook.
        playbook_parameters (str): Parameters of the playbook.

    Returns:
        str: Playbook file path generated.
    """
    tasks = _delete_files(files_path)

    parameters = dict(**playbook_parameters) if playbook_parameters else {}
    parameters.update({'name': 'delete_files', 'tasks_list': tasks})

    return _build_playbook(parameters)


def wait_seconds(num_seconds, playbook_parameters=None):
    """Generate a playbook to wait.

    Args:
        num_seconds (int): Number of second to generate the playbook.
        playbook_parameters (str): Parameters of the playbook.

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
    """Return a clean operating system.

    Args:
        os_system (str): Operating system to create the playbook.

    Raises:
        ValueError: If the os_system has an invalid value.

    Returns:
        str: Operating system [centos or ubuntu].
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
    """Create a playbook to download a package.

    Args:
        package_url (str): URL of the package to be downloaded.
        package_destination (str): Destination where the package will be stored

    Returns:
        str: The playbook task created.
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


def _start_wazuh_manager_systemd_service():
    """Create a playbook to start a manager with systemd command.

    Returns:
        str: The playbook task created.
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
    """Create a playbook to start an agent with systemd command.

    Returns:
        str: The playbook task created.
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
    """Create a playbook to stop a manager with systemd command.

    Returns:
        str: The playbook task created.
    """
    return [
        AnsibleTask({
            'name': 'Start Wazuh Manager service with systemd',
            'become': True,
            'ansible.builtin.systemd': {
              'state': 'stopped',
              'name': 'wazuh-manager'
            }
        })
    ]


def _stop_wazuh_agent_systemd_service():
    """Create a playbook to stop an agent with systemd command.

    Returns:
        str: The playbook task created.
    """
    return [
        AnsibleTask({
            'name': 'Start Wazuh Agent service with systemd',
            'become': True,
            'ansible.builtin.systemd': {
              'state': 'stopped',
              'name': 'wazuh-agent'
            }
        })
    ]


def _start_wazuh_control_service(wazuh_target):
    """Create a playbook to start a manager or agent with wazuh-control command.

    Args:
        wazuh_target (str): Wazuh target [manager or agent].

    Returns:
        str: The playbook task created.
    """
    return [
        AnsibleTask({
            'name': f"Start Wazuh {wazuh_target} service with systemd",
            'become': True,
            'shell': '/var/ossec/bin/wazuh-control start',
        })
    ]


def _stop_wazuh_control_service(wazuh_target):
    """Create a playbook to stop a manager or agent with wazuh-control command.

    Args:
        wazuh_target (str): Wazuh target [manager or agent].

    Returns:
        str: The playbook task created.
    """
    return [
        AnsibleTask({
            'name': f"Stop Wazuh {wazuh_target} service with systemd",
            'become': True,
            'shell': '/var/ossec/bin/wazuh-control stop',
        })
    ]


def _install_wazuh_rpm(package_name, package_url, package_destination, wazuh_target):
    """Create a playbook to install a RPM package of a manager or agent.

    Args:
        package_name (str): Name of the package to be installed.
        package_url (str): URL of the package to be installed.
        package_destination (str): Destination folder where the package will be downloaded.
        wazuh_target (str): Wazuh target [manager or agent].

    Returns:
        str: The playbook task created.
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
        tasks.extend(_start_wazuh_agent_systemd_service())

    return tasks


def _install_wazuh_deb(package_name, package_url, package_destination, wazuh_target):
    """Create a playbook to install a DEB package of a manager or agent.

    Args:
        package_name (str): Name of the package to be installed.
        package_url (str): URL of the package to be installed.
        package_destination (str): Destination folder where the package will be downloaded.
        wazuh_target (str): Wazuh target [manager or agent].

    Returns:
        str: The playbook task created.
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
        tasks.extend(_start_wazuh_agent_systemd_service())

    return tasks


def _upgrade_wazuh_rpm(package_name, package_url, package_destination):
    """Create a playbook to upgrade a RPM package.

    Args:
        package_name (str): Name of the package to be installed.
        package_url (str): URL of the package to be installed.
        package_destination (str): Destination folder where the package will be downloaded.

    Returns:
        str: The playbook task created.
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
    """Create a playbook to upgrade a DEB package.

    Args:
        package_name (str): Name of the package to be installed.
        package_url (str): URL of the package to be installed.
        package_destination (str): Destination folder where the package will be downloaded.

    Returns:
        str: The playbook task created.
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
    """Create a playbook to uninstall a RPM package of a manager or agent.

    Args:
        wazuh_target (str): Wazuh target [manager or agent].

    Returns:
        str: The playbook task created.
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
    """Create a playbook to uninstall a DEB package of a manager or agent.

    Args:
        wazuh_target (str): Wazuh target [manager or agent].

    Returns:
        str: The playbook task created.
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


def _run_linux_commands(commands):
    """Create a playbook to run a command in linux.

    Args:
        commands (str): Command to be run.

    Returns:
        str: The playbook task created.
    """
    return [
       AnsibleTask({
           'name': f"Run Command {command}",
           'shell': command
        }) for command in commands
    ]


def _download_files(files_data):
    """Create a playbook to download a file.

    Args:
        files_data (dict): File URL and file destination {file_url: file_destination}.

    Returns:
        str: The playbook task created.
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
    """Create a playbook to fetct a file.

    Args:
        files_data (dict): Remote path  and destination path to fetch {remote_path: local_destination_path}.

    Returns:
        str: The playbook task created.
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


def _delete_files(files_path):
    """Create a playbook to delete files.

    Args:
        files_path (list): Path of the files to be deleted [path1, path2, ...].

    Returns:
        str: The playbook task created.
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
    """Create a playbook to wait.

    Args:
        num_seconds (int): Nomber of seconds to wait.

    Returns:
        str: The playbook task created.
    """
    return [
        AnsibleTask({
            'name': f"Wait {num_seconds} seconds",
            'pause': {
                'seconds': num_seconds,
            }
        })
    ]
