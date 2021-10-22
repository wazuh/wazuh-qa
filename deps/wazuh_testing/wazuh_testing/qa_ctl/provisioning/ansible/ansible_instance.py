import yaml
import json
from abc import ABC

class AnsibleInstance(ABC):
    """Represent the necessary attributes of an instance to be specified in an ansible inventory.

    Args:
        host (str): Ip or hostname.
        ansible_user (str): Host connection user

    Attributes:
        host (str): Ip or hostname.
        ansible_user (str): Host connection user
    """
    def __init__(self, host, host_vars=None):
        self.host = host
        self.host_vars = host_vars
