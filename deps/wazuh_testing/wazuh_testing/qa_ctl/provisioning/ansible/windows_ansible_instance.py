import yaml
import json

from wazuh_testing.qa_ctl.provisioning.ansible.ansible_instance import AnsibleInstance


class WindowsAnsibleInstance(AnsibleInstance):
    """Represent the necessary attributes of an instance to be specified in an ansible inventory.

    Args:
        host (str): Ip or hostname.
        ansible_connection (str): Connection method.
        ansible_port (int): Remote connection port.
        ansible_user (str): Host connection user
        ansible_password (str): Host connection user password
        ansible_python_interpreter (str): Python interpreter path in the remote host.
        host_vars (dict): Set of custom variables to add to that host.
    """
    def __init__(self, host, ansible_connection='winrm', ansible_port=5985, ansible_user='vagrant',
                 ansible_password='vagrant', host_vars=None, ansible_python_interpreter=None):
        super().__init__(host, ansible_connection, ansible_port, ansible_user, ansible_password,
                         ansible_python_interpreter, host_vars)

    def __str__(self):
        """Define how the class object is to be displayed."""
        data = {
            'host_information': {
                'host': self.host, 'ansible_connection': self.ansible_connection,
                'ansible_port': self.ansible_port, 'ansible_user': self.ansible_user,
                'ansible_password': self.ansible_password,
                'ansible_python_interpreter': self.ansible_python_interpreter, 'host_vars': self.host_vars
            }
        }

        return yaml.dump(data, allow_unicode=True, sort_keys=False)

    def __repr__(self):
        """Representation of the object of the class in string format"""
        return json.dumps({
            'host': self.host, 'ansible_connection': self.ansible_connection,
            'ansible_port': self.ansible_port, 'ansible_user': self.ansible_user,
            'ansible_password': self.ansible_password, 'ansible_python_interpreter': self.ansible_python_interpreter,
            'host_vars': self.host_vars
        })
