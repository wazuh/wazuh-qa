from wazuh_testing.qa_ctl.provisioning.ansible.ansible_task import AnsibleTask
from wazuh_testing.qa_ctl.provisioning.ansible.ansible_runner import AnsibleRunner
from wazuh_testing.qa_ctl.provisioning.ansible.ansible_instance import AnsibleInstance
from wazuh_testing.qa_ctl.provisioning.ansible.ansible_inventory import AnsibleInventory
from wazuh_testing.tools.exceptions import AnsibleException


def _ansible_runner(inventory_file_path, playbook_parameters, ansible_output=False, log_ansible_error=True):
    """Ansible runner method. Launch the playbook tasks with the indicated host.

    Args:
        inventory_file_path (str): Path where is located the inventory file.
        playbook_parameters (dict): Playbook parameters to create and launch.
        ansible_output (boolean): True for showing ansible output, False otherwise.
        log_ansible_error (boolean): True for logging the error exception message if any.

    Returns:
        AnsibleOutput: Result of the ansible run.
    """
    tasks_result = AnsibleRunner.run_ephemeral_tasks(inventory_file_path, playbook_parameters, output=ansible_output,
                                                     log_ansible_error=log_ansible_error)
    return tasks_result


def copy_files_to_remote(inventory_file_path, hosts, files_path, dest_path, become=False, ansible_output=False):
    """Copy local files to remote hosts.

    Args:
        inventory_file_path (str): Path where is located the inventory file.
        hosts (str): Inventory hosts where to run the tasks.
        files_path (list(str)): Files path of the files that will be copied to the remote host.
        dest_path (str): Path of the remote host where place the copied files.
        become (boolean): True if the tasks have to be launch as root user, False otherwise
        ansible_output (boolean): True for showing ansible output, False otherwise.

    Returns:
        AnsibleOutput: Result of the ansible run.
    """
    tasks_list = [
        AnsibleTask({
            'name': f"Create path {dest_path} for UNIX systems",
            'file': {
                'path': dest_path,
                'state': 'directory',
                'mode': '0775'
            },
            'when': 'ansible_distribution is not search("Microsoft Windows")'
        }),
        AnsibleTask({
            'name': 'Copy files to remote for UNIX systems',
            'copy': {
                'src': "{{ item.src }}",
                'dest': "{{ item.dest }}/"
            },
            'with_items': [{'src': file, 'dest': dest_path} for file in files_path],
            'when': 'ansible_distribution is not search("Microsoft Windows")'
        }),
        AnsibleTask({
            'name': f"Create {dest_path} path for Windows systems",
            'win_file': {
                'path': dest_path,
                'state': 'directory',
                'mode': '0775'
            },
            'when': 'ansible_distribution is search("Microsoft Windows")'
        }),
        AnsibleTask({
            'name': 'Copy files to remote for Windows systems',
            'win_copy': {
                'src': "{{ item.src }}",
                'dest': "{{ item.dest }}/"
            },
            'with_items': [{'src': file, 'dest': dest_path} for file in files_path],
            'when': 'ansible_distribution is search("Microsoft Windows")'
        })
    ]

    return _ansible_runner(inventory_file_path, {'tasks_list': tasks_list, 'hosts': hosts, 'gather_facts': True,
                                                 'become': become}, ansible_output)


def remove_paths(inventory_file_path, hosts, paths_to_delete, become=False, ansible_output=False):
    """Remove folders recursively in remote hosts.

    Args:
        inventory_file_path (str): Path where is located the inventory file.
        hosts (str): Inventory hosts where to run the tasks.
        paths_to_delete (list(str)): Paths of the folders to delete recursively.
        become (boolean): True if the tasks have to be launch as root user, False otherwise
        ansible_output (boolean): True for showing ansible output, False otherwise.

    Returns:
        AnsibleOutput: Result of the ansible run.
    """
    tasks_list = [
        AnsibleTask({
            'name': f"Delete {paths_to_delete} path for UNIX systems",
            'file': {
                'state': 'absent',
                'path': "{{ item }}"
            },
            'with_items': paths_to_delete,
            'when': 'ansible_distribution is not search("Microsoft Windows")'
        }),
        AnsibleTask({
            'name': f"Delete {paths_to_delete} path for Windows systems",
            'win_file': {
                'state': 'absent',
                'path': "{{ item }}"
            },
            'with_items': paths_to_delete,
            'when': 'ansible_distribution is search("Microsoft Windows")'
        }),
    ]

    return _ansible_runner(inventory_file_path, {'tasks_list': tasks_list, 'hosts': hosts, 'gather_facts': True,
                                                 'become': become}, ansible_output)


def launch_remote_commands(inventory_file_path, hosts, commands, become=False, ansible_output=False):
    """Launch remote commands in the specified hosts.

    Args:
        inventory_file_path (str): Path where is located the inventory file.
        hosts (str): Inventory hosts where to run the tasks.
        commands (list(str)): Commands to launch in remote hosts.
        become (boolean): True if the tasks have to be launch as root user, False otherwise
        ansible_output (boolean): True for showing ansible output, False otherwise.

    Returns:
        AnsibleOutput: Result of the ansible run.
    """
    tasks_list = [
        AnsibleTask({
            'name': 'Running command list on UNIX systems',
            'command': "{{ item }}",
            'with_items': commands,
            'when': 'ansible_distribution is not search("Microsoft Windows")'
        }),
        AnsibleTask({
            'name': 'Running command list on Windows systems',
            'win_command': "{{ item }}",
            'with_items': commands,
            'when': 'ansible_distribution is search("Microsoft Windows")'
        })
    ]

    return _ansible_runner(inventory_file_path, {'tasks_list': tasks_list, 'hosts': hosts, 'gather_facts': True,
                                                 'become': become}, ansible_output)


def check_windows_ansible_credentials(user, password, log_ansible_error=False):
    """Check if the windows ansible credentials are correct.

    This method must be run in a Windows WSL.

    Args:
        user (str): Windows user.
        password (str): Windows user password.
        log_ansible_error (boolean): True for logging the error exception message if any.

    Returns:
        boolean: True if credentials are correct, False otherwise.
    """
    inventory = AnsibleInventory([AnsibleInstance('127.0.0.1',  connection_user=user,
                                                  connection_user_password=password,
                                                  connection_method='winrm',
                                                  connection_port='5986')
                                ])
    inventory_file_path = inventory.inventory_file_path
    tasks_list = [
         AnsibleTask({
            'debug': {
                'msg': 'Hello world'
            }
        }),

    ]

    try:
        _ansible_runner(inventory_file_path, {'tasks_list': tasks_list, 'hosts': '127.0.0.1', 'gather_facts': True,
                                              'become': False}, ansible_output=False,
                                              log_ansible_error=log_ansible_error)
        return True
    except AnsibleException:
        return False
