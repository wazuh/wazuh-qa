import os
from tempfile import gettempdir

from wazuh_testing.qa_ctl.provisioning.ansible.ansible_playbook import AnsiblePlaybook
from wazuh_testing.qa_ctl.provisioning.ansible.ansible_task import AnsibleTask
from wazuh_testing.tools.time import get_current_timestamp


class PlaybookGenerator:

    OS_SYSTEM = ['centos', 'ubuntu']
    OS_PLATFORM = ['linux', 'windows']
    PACKAGE_MANAGER = {'centos': 'RPM', 'ubuntu': 'DEB'}
    PLAYBOOSK_PATH = os.path.join(gettempdir(), 'wazuh_playbooks')

    @staticmethod
    def validate_playbook_parameters(parameters):
        required_parameters = ['tasks_list']

        for required_parameter in required_parameters:
            if required_parameter not in parameters.keys():
                raise ValueError(f"{required_parameter} is a required parameter to generate the playbook.")

    @staticmethod
    def install_wazuh(package_name, package_url, package_destination, os_system, os_platform, playbook_parameters=None):
        tasks = []
        _os_system = _clean_os_system(os_system)

        if os_platform == 'linux':
            if PlaybookGenerator.PACKAGE_MANAGER[_os_system] == 'RPM':
                tasks = _install_wazuh_rpm(package_url, package_destination)
            elif PlaybookGenerator.PACKAGE_MANAGER[_os_system] == 'DEB':
                tasks = _install_wazuh_deb(package_name, package_url, package_destination)
            else:
                raise ValueError(f"{os_system} is not supported in PlaybookGenerator")
        else:
            raise ValueError(f"{os_platform} is not supported in PlaybookGenerator")

        parameters = dict(**playbook_parameters) if playbook_parameters else {}
        parameters.update({'name': 'install_wazuh', 'tasks_list': tasks})

        return _build_playbook(parameters)

    @staticmethod
    def upgrade_wazuh(package_name, package_url, package_destination, os_system, os_platform, playbook_parameters=None):
        tasks = []
        _os_system = _clean_os_system(os_system)

        if os_platform == 'linux':
            if PlaybookGenerator.PACKAGE_MANAGER[_os_system] == 'RPM':
                tasks = _upgrade_wazuh_rpm(package_name, package_url, package_destination)
            elif PlaybookGenerator.PACKAGE_MANAGER[_os_system] == 'DEB':
                tasks = _upgrade_wazuh_deb(package_name, package_url, package_destination)
            else:
                raise ValueError(f"{os_system} is not supported in PlaybookGenerator")
        else:
            raise ValueError(f"{os_platform} is not supported in PlaybookGenerator")

        parameters = dict(**playbook_parameters) if playbook_parameters else {}
        parameters.update({'name': 'upgrade_wazuh', 'tasks_list': tasks})

        return _build_playbook(parameters)

    @staticmethod
    def uninstall_wazuh(os_system, os_platform, playbook_parameters=None):
        tasks = []
        _os_system = _clean_os_system(os_system)

        if os_platform == 'linux':
            if PlaybookGenerator.PACKAGE_MANAGER[_os_system] == 'RPM':
                tasks = _uninstall_wazuh_rpm()
            elif PlaybookGenerator.PACKAGE_MANAGER[_os_system] == 'DEB':
                tasks = _uninstall_wazuh_deb()
            else:
                raise ValueError(f"{os_system} is not supported in PlaybookGenerator")
        else:
            raise ValueError(f"{os_platform} is not supported in PlaybookGenerator")

        parameters = dict(**playbook_parameters) if playbook_parameters else {}
        parameters.update({'name': 'uninstall_wazuh', 'tasks_list': tasks})

        return _build_playbook(parameters)

    @staticmethod
    def run_linux_commands(commands, playbook_parameters=None):
        tasks = _run_linux_commands(commands)

        parameters = dict(**playbook_parameters) if playbook_parameters else {}
        parameters.update({'name': 'run_linux_commands', 'tasks_list': tasks})

        return _build_playbook(parameters)

    @staticmethod
    def download_files(files_data, playbook_parameters=None):
        tasks = _download_files(files_data)

        parameters = dict(**playbook_parameters) if playbook_parameters else {}
        parameters.update({'name': 'download_files', 'tasks_list': tasks})

        return _build_playbook(parameters)

    @staticmethod
    def fetch_files(files_data, playbook_parameters=None):
        tasks = _fetch_files(files_data)

        parameters = dict(**playbook_parameters) if playbook_parameters else {}
        parameters.update({'name': 'fetch_files', 'tasks_list': tasks})

        return _build_playbook(parameters)


### PLAYBOOK BUILDER UTILS FUNCTIONS ###


def _build_playbook(parameters):
    # Validate if the required parameters to build the playbook are specified.
    PlaybookGenerator.validate_playbook_parameters(parameters)

    current_timestamp = str(get_current_timestamp()).replace('.', '_')
    playbook_file_path = os.path.join(PlaybookGenerator.PLAYBOOSK_PATH,
                                      f"{parameters['name']}_{current_timestamp}.yaml")

    playbook_parameters = dict(**parameters) if parameters else {}
    playbook_parameters.update({'playbook_file_path': playbook_file_path, 'generate_file': True})

    playbook = AnsiblePlaybook(**playbook_parameters)

    return playbook.playbook_file_path


def _clean_os_system(os_system):
    if 'centos' in os_system:
        return 'centos'
    elif 'ubuntu' in os_system:
        return 'ubuntu'
    else:
        raise ValueError(f"{os_system} is not allowed in PlaybookGenerator class")


### PLAYBOOK TASKS ###


def _download_wazuh_package(package_url, package_destination):
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


def _start_wazuh_systemd_service():
    return [
        AnsibleTask({
            'name': 'Start Wazuh service with systemd',
            'become': True,
            'shell': 'systemctl start wazuh-*'
        })
    ]


def _install_wazuh_rpm(package_url, package_destination):
    tasks = []

    tasks.extend(_download_wazuh_package(package_url, package_destination))
    tasks.append(
        AnsibleTask({
            'name': 'Install Wazuh RPM package',
            'become': True,
            'shell': 'yum install -y wazuh-*',
            'args': {
                'chdir': package_destination
            }
        })
    )
    tasks.extend(_start_wazuh_systemd_service())

    return tasks


def _install_wazuh_deb(package_name, package_url, package_destination):
    tasks = []

    tasks.extend(_download_wazuh_package(package_url, package_destination))
    tasks.append(
        AnsibleTask({
            'name': 'Install Wazuh DEB package',
            'become': True,
            'apt': {'deb': f'{package_destination}/{package_name}'},
        })
    )
    tasks.extend(_start_wazuh_systemd_service())

    return tasks


def _upgrade_wazuh_rpm(package_name, package_url, package_destination):
    tasks = []

    tasks.extend(_download_wazuh_package(package_url, package_destination))

    tasks.append(
        AnsibleTask({
            'name': 'Upgrade wazuh RPM package',
            'become': True,
            'yum':{
                'name': f"{package_destination}/{package_name}",
                'state': 'latest'
            },
            'register':'rpm_upgrade',
            'retries': 6,
            'delay': 10,
            'until': 'rpm_upgrade is success',
        })
    )

    return tasks


def _upgrade_wazuh_deb(package_name, package_url, package_destination):
    tasks = []

    tasks.extend(_download_wazuh_package(package_url, package_destination))

    tasks.append(
        AnsibleTask({
            'name': 'Upgrade wazuh DEB package',
            'become': True,
            'apt':{
                'deb': f"{package_destination}/{package_name}",
                'state': 'present',
                'update_cache':True
            },
            'register':'deb_upgrade',
            'retries': 6,
            'delay': 10,
            'until': 'deb_upgrade is success',
        })
    )

    return tasks


def _uninstall_wazuh_rpm():
    return [
        AnsibleTask({
            'name': 'Uninstall wazuh RPM package',
            'become': True,
            'yum':{
                'name': 'wazuh-*',
                'state': 'absent'
            },
            'ignore_errors':True
        }),
        AnsibleTask({
            'name': 'Delete /var/ossec directory',
            'become': True,
            'file':{
                'state': 'absent',
                'path': '/var/ossec/'
            },
            'ignore_errors':True
        })
    ]


def _uninstall_wazuh_deb():
    return [
        AnsibleTask({
            'name': 'Uninstall wazuh DEB package',
            'become': True,
            'apt': {
                'name':'wazuh-*',
                'state':'absent',
                'purge':True
            },
            'ignore_errors':True
        })
    ]


def _run_linux_commands(commands):
    return [
       AnsibleTask({
           'name': f"Run Command {command}",
           'shell': command
        }) for command in commands
    ]


def _download_files(files_data):
    """
    files_data -> {file_url: file_destination}
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
    """
    files_data -> {remote_path: local_destination_path}
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
