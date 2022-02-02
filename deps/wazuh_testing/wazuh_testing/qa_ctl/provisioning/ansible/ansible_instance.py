import yaml
import json
from abc import ABC


class AnsibleInstance(ABC):
    """Represent the necessary attributes of an instance to be specified in an ansible inventory.

    Args:
        host (str): Ip or hostname.
        ansible_connection (str): Connection method.
        ansible_port (int): Remote connection port.
        ansible_user (str): Host connection user.
        ansible_password (str): Host connection user password.
        ansible_python_interpreter (str): Python interpreter path in the remote host.
        host_vars (dict): Set of custom variables to add to that host.

    Attributes:
        host (str): Ip or hostname.
        ansible_connection (str): Connection method.
        ansible_port (int): Remote connection port.
        ansible_user (str): Host connection user.
        ansible_password (str): Host connection user password.
        ansible_python_interpreter (str): Python interpreter path in the remote host.
        host_vars (dict): Set of custom variables to add to that host.
    """
    def __init__(self, host, ansible_connection, ansible_port, ansible_user, ansible_password,
                 ansible_python_interpreter=None, host_vars=None):
        self.host = host
        self.ansible_connection = ansible_connection
        self.ansible_port = ansible_port
        self.ansible_user = ansible_user
        self.ansible_password = ansible_password
        self.ansible_python_interpreter = ansible_python_interpreter
        self.host_vars = host_vars
