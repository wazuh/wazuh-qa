from wazuh_testing.qa_ctl.provisioning.ansible.unix_ansible_instance import UnixAnsibleInstance
from wazuh_testing.qa_ctl.provisioning.ansible.windows_ansible_instance import WindowsAnsibleInstance


def read_ansible_instance(host_info):
    """Read every host info and generate the AnsibleInstance object.

    Args:
        host_info (dict): Dict with the host info needed coming from config file.

    Returns:
        instance (AnsibleInstance): Contains the AnsibleInstance for a given host.
    """
    extra_vars = None if 'host_vars' not in host_info else host_info['host_vars']
    private_key_path = None if 'local_private_key_file_path' not in host_info \
        else host_info['local_private_key_file_path']

    if host_info['system'] == 'windows':
        instance = WindowsAnsibleInstance(
            host=host_info['host'],
            ansible_connection=host_info['ansible_connection'],
            ansible_port=host_info['ansible_port'],
            ansible_user=host_info['ansible_user'],
            ansible_password=host_info['ansible_password'],
            ansible_python_interpreter=host_info['ansible_python_interpreter'],
            host_vars=extra_vars
        )
    else:
        instance = UnixAnsibleInstance(
            host=host_info['host'],
            ansible_connection=host_info['ansible_connection'],
            ansible_port=host_info['ansible_port'],
            ansible_user=host_info['ansible_user'],
            ansible_password=host_info['ansible_password'],
            host_vars=extra_vars,
            ansible_ssh_private_key_file=private_key_path,
            ansible_python_interpreter=host_info['ansible_python_interpreter']
        )

    return instance
