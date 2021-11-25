
import json

class ConfigInstance:
    """Represent a basic instance to be added later in the qa-ctl configuration file.

    Args:
        name (str): Name assigned to the VM.
        os (str): Operating system assigned to the VM.
        cpu (int): Number of CPUs assigned to the VM.
        memory (int): Number of RAM bytes assigned to the VM.
        ip (str): Ip address assigned to the VM.

    Attributes:
        name (str): Name assigned to the VM.
        os (str): Operating system assigned to the VM.
        cpu (int): Number of CPUs assigned to the VM.
        memory (int): Number of RAM bytes assigned to the VM.
        ip (str): Ip address assigned to the VM.
    """
    def __init__(self, name, os, memory=1024, cpu=1, ip=None):
        self.name = name
        self.os = os
        self.memory = memory
        self.cpu = cpu
        self.ip = ip

    def __str__(self):
        """Define how the class object is to be displayed."""
        return f"name: {self.name}\nos: {self.os}\nmemory: {self.memory}\ncpu: {self.cpu}\nip: {self.ip}\n"

    def __repr__(self):
        """Representation of the object of the class in string format"""
        return json.dumps( {
            'name': self.name,
            'os': self.os,
            'memory': self.memory,
            'cpu': self.cpu,
            'ip': self.ip,
        })
