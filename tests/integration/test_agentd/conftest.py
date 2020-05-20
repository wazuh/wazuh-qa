import pytest
import socket

DEFAULT_VALUES = {
    'enabled' : 'yes', 
    'manager_address' : None, 
    'port' : 1515, 
    'agent_name' : socket.gethostname(), 
    'groups' : None, 
    'agent_address' : '127.0.0.1', 
    'use_source_ip' : 'no'
}
class AgentAuthParser:

    def __init__(self, server_address=None, BINARY_PATH='/var/ossec/bin/agent-auth', sudo=False):
        self._command = []
        if sudo:
            self._command.append('sudo')
        self._command += [BINARY_PATH]
        if server_address:
            self._command += ['-m', server_address]
    
    def get_command(self):
        return self._command

    def add_agent_name(self, agent_name):
        self._command += ['-A', agent_name]

    def add_agent_adress(self, agent_adress):
        self._command += ['-I', agent_adress]

    def add_auto_negotiation(self):
        self._command += ['-a']

    def add_ciphers(self, ciphers):
        self._command += ['-c', ciphers]

    def add_agent_certificates(self, key, cert):
        self._command += ['-k', key, '-x', cert]

    def add_manager_ca(self, ca_cert):
        self._command += ['-v', ca_cert]
    
    def use_source_ip(self):
        self._command += ['-i']

    def add_password(self, password=None, isFile=False, path=None):
        with open(path, 'w') as f:
            if isFile and password:
                f.write(password)
            elif password:
                self._command += ['-P', password]
