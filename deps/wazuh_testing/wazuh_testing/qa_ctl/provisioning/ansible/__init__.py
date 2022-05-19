import sys
import os
from pathlib import Path

from wazuh_testing.qa_ctl.provisioning.ansible.unix_ansible_instance import UnixAnsibleInstance
from wazuh_testing.qa_ctl.provisioning.ansible.windows_ansible_instance import WindowsAnsibleInstance
from wazuh_testing.qa_ctl.provisioning.local_actions import run_local_command_returning_output


def read_ansible_instance(host_info):
    """Read every host info and generate the AnsibleInstance object.

    Args:
        host_info (dict): Dict with the host info needed coming from config file.

    Returns:
        instance (AnsibleInstance): Contains the AnsibleInstance for a given host.
    """
    extra_vars = None if 'host_vars' not in host_info else host_info['host_vars']
    ansible_private_key_path = None if 'ansible_ssh_private_key_file' not in host_info \
        else host_info['ansible_ssh_private_key_file']
    ansible_password = None if 'ansible_password' not in host_info else host_info['ansible_password']

    if host_info['system'] == 'windows':
        instance = WindowsAnsibleInstance(
            host=host_info['host'],
            ansible_connection=host_info['ansible_connection'],
            ansible_port=host_info['ansible_port'],
            ansible_user=host_info['ansible_user'],
            ansible_password=ansible_password,
            ansible_python_interpreter=host_info['ansible_python_interpreter'],
            host_vars=extra_vars
        )
    else:
        instance = UnixAnsibleInstance(
            host=host_info['host'],
            ansible_connection=host_info['ansible_connection'],
            ansible_port=host_info['ansible_port'],
            ansible_user=host_info['ansible_user'],
            ansible_password=ansible_password,
            host_vars=extra_vars,
            ansible_ssh_private_key_file=ansible_private_key_path,
            ansible_python_interpreter=host_info['ansible_python_interpreter']
        )

    return instance


def remove_known_host(host_ip, logger=None):
    """Remove an IP host from SSH known_hosts file.

    Args:
        host_ip (str): Host IP to remove from SSH known_host file.
        logger (logging.Logging): Logger where log the messages.
    """
    if sys.platform != 'win32':
        known_host_file = os.path.join(str(Path.home()), '.ssh', 'known_hosts')
        if os.path.exists(known_host_file):
            if logger:
                logger.debug(f"Removing {host_ip} from {known_host_file} file")

            run_local_command_returning_output(f"ssh-keygen -f {known_host_file} -R {host_ip} &> /dev/null")
