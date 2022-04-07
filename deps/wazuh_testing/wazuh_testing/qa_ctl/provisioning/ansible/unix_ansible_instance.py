import yaml
import json

from wazuh_testing.qa_ctl.provisioning.ansible.ansible_instance import AnsibleInstance


class UnixAnsibleInstance(AnsibleInstance):
    """Represent the necessary attributes of an instance to be specified in an ansible inventory.

    Args:
        host (str): Ip or hostname.
        ansible_connection (str): Connection method.
        ansible_port (int): Remote connection port.
        ansible_user (str): Host connection user
        ansible_password (str): Host connection user password
        host_vars (dict): Set of custom variables to add to that host.
        ansible_python_interpreter (str): Python interpreter path in the remote host.
        ansible_ssh_private_key_file (str): Path where is located the private key to authenticate the user.

    Attributes:
        ansible_ssh_private_key_file (str): Path where is located the private key to authenticate the user.
    """
    def __init__(self, host, ansible_connection='ssh', ansible_port=22, ansible_user='vagrant',
                 ansible_password='vagrant', host_vars=None, ansible_python_interpreter='/usr/bin/python',
                 ansible_ssh_private_key_file=None):
        self.ansible_ssh_private_key_file = ansible_ssh_private_key_file

        super().__init__(host, ansible_connection, ansible_port, ansible_user, ansible_password,
                         ansible_python_interpreter, host_vars)

    def __str__(self):
        """Define how the class object is to be displayed."""
        data = {
            'host_information': {
                'host': self.host, 'ansible_connection': self.ansible_connection,
                'ansible_port': self.ansible_port, 'ansible_user': self.ansible_user,
                'ansible_password': self.ansible_password, 'host_vars': self.host_vars,
                'ansible_python_interpreter': self.ansible_python_interpreter,
                'ansible_ssh_private_key_file': self.ansible_ssh_private_key_file
            }
        }

        return yaml.dump(data, allow_unicode=True, sort_keys=False)

    def __repr__(self):
        """Representation of the object of the class in string format"""
        return json.dumps({
            'host': self.host, 'ansible_connection': self.ansible_connection,
            'ansible_port': self.ansible_port, 'ansible_user': self.ansible_user,
            'ansible_password': self.ansible_password, 'host_vars': self.host_vars,
            'ansible_python_interpreter': self.ansible_python_interpreter,
            'ansible_ssh_private_key_file': self.ansible_ssh_private_key_file
        })
