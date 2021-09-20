from wazuh_testing.qa_ctl.provisioning.ansible.ansible_task import AnsibleTask
from wazuh_testing.qa_ctl.provisioning.ansible.ansible_runner import AnsibleRunner


def _ansible_runner(inventory_file_path, playbook_parameters, ansible_output=False):
    tasks_result = AnsibleRunner.run_ephemeral_tasks(inventory_file_path, playbook_parameters, output=ansible_output)

    return tasks_result


def copy_files_to_remote(inventory_file_path, hosts, files_path, dest_path, become=False, ansible_output=False):
    tasks_list = [
        AnsibleTask({
            'name': f"Create path {dest_path} when system is not Windows",
            'file': {
                'path': dest_path,
                'state': 'directory',
                'mode': '0775'
            },
            'when': 'ansible_distribution is not search("Microsoft Windows")'
        }),
        AnsibleTask({
            'name': 'Copy files to remote when system is not Windows',
            'copy': {
                'src': "{{ item.src }}",
                'dest': "{{ item.dest }}/"
            },
            'with_items': [{'src': file, 'dest': dest_path} for file in files_path],
            'when': 'ansible_distribution is not search("Microsoft Windows")'
        }),
        AnsibleTask({
            'name': f"Create {dest_path} path when system is Windows",
            'win_file': {
                'path': dest_path,
                'state': 'directory',
                'mode': '0775'
            },
            'when': 'ansible_distribution is search("Microsoft Windows")'
        }),
        AnsibleTask({
            'name': 'Copy files to remote when system is Windows',
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
    tasks_list = [
        AnsibleTask({
            'name': f"Delete {paths_to_delete} path (when system is not Windows)",
            'file': {
                'state': 'absent',
                'path': "{{ item }}"
            },
            'with_items': paths_to_delete,
            'when': 'ansible_distribution is not search("Microsoft Windows")'
        }),
        AnsibleTask({
            'name': f"Delete {paths_to_delete} path (when system is not Windows)",
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

