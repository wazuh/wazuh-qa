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
