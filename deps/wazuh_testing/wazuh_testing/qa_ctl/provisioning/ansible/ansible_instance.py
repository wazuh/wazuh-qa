import yaml
import json


class AnsibleInstance():
    """Represent the necessary attributes of an instance to be specified in an ansible inventory.

    Args:
        host (str): Ip or hostname.
        connection_user (str): Host connection user
        connection_user_password (str): Host connection user password
        ssh_private_key_file_path (str): Path where is located the private key to authenticate the user.
        host_vars (dict): Set of custom variables to add to that host.
        connection_method (str): Connection method: smart, ssh or paramiko.
        connection_port (int): Remote ssh connection port.
        ansible_python_interpreter (str): Python interpreter path in the remote host.

    Attributes:
        host (str): Ip or hostname.
        connection_user (str): Host connection user
        connection_user_password (str): Host connection user password
        ssh_private_key_file_path (str): Path where is located the private key to authenticate the user.
        host_vars (dict): Set of custom variables to add to that host.
        connection_method (str): Connection method: smart, ssh or paramiko.
        connection_port (int): Remote ssh connection port.
        ansible_python_interpreter (str): Python interpreter path in the remote host.
    """
    def __init__(self, host, connection_user, connection_user_password=None, ssh_private_key_file_path=None,
                 host_vars=None, connection_method='ssh', connection_port=22,
                 ansible_python_interpreter='/usr/bin/python'):
        self.host = host
        self.host_vars = host_vars
        self.connection_method = connection_method
        self.connection_port = connection_port
        self.connection_user = connection_user
        self.connection_user_password = connection_user_password
        self.ssh_private_key_file_path = ssh_private_key_file_path
        self.ansible_python_interpreter = ansible_python_interpreter

    def __str__(self):
        """Define how the class object is to be displayed."""
        data = {'host_information': {'host': self.host, 'connection_method': self.connection_method,
                                     'connection_port': self.connection_port, 'connection_user': self.connection_user,
                                     'password': self.connection_user_password,
                                     'connection_user_password': self.connection_user_password,
                                     'ssh_private_key_file_path': self.ssh_private_key_file_path,
                                     'ansible_python_interpreter': self.ansible_python_interpreter
                                     }
                }

        return yaml.dump(data, allow_unicode=True, sort_keys=False)

    def __repr__(self):
        """Representation of the object of the class in string format"""
        return json.dumps({'host': self.host, 'host_vars': self.host_vars, 'connection_method': self.connection_method,
                           'connection_port': self.connection_port, 'connection_user': self.connection_user,
                           'connection_user_password': self.connection_user_password,
                           'ssh_private_key_file_path': self.ssh_private_key_file_path,
                           'ansible_python_interpreter': self.ansible_python_interpreter})
