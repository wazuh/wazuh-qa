# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest
import os

from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import QueueMonitor, FileMonitor
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools import WAZUH_PATH, LOG_FILE_PATH
from wazuh_testing.tools.authd_sim import AuthdSimulator
from wazuh_testing.tools.remoted_sim import RemotedSimulator
from wazuh_testing.tools.services import control_service
from conftest import *
from time import sleep
# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.agent]

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')

params = [
{
    'SERVER_ADDRESS': '127.0.0.1',
    'REMOTED_PORT': 1514,
    'PROTOCOL' : 'tcp',
},
{
    'SERVER_ADDRESS': '127.0.0.1',
    'REMOTED_PORT': 1514,
    'PROTOCOL' : 'udp',
}
]
metadata = [
    {'PROTOCOL': 'tcp'},
    {'PROTOCOL': 'udp'}
]

configurations = load_wazuh_configurations(configurations_path, __name__, params=params, metadata=metadata)

log_monitor_paths = []

receiver_sockets_params = []

monitored_sockets_params = []

receiver_sockets, monitored_sockets, log_monitors = None, None, None  # Set in the fixtures

authd_server = AuthdSimulator(params[0]['SERVER_ADDRESS'], key_path=SERVER_KEY_PATH, cert_path=SERVER_CERT_PATH)

def set_debug_mode():
    if platform.system() == 'win32' or platform.system() == 'Windows':
        local_int_conf_path=os.path.join(WAZUH_PATH, 'local_internal_options.conf')
        with  open(local_int_conf_path, 'r') as local_file_read:
            lines = local_file_read.readlines()
            for line in lines: 
                if line == 'windows.debug=2\n':
                    return
        with  open(local_int_conf_path, 'a') as local_file_write:
            local_file_write.write('\nwindows.debug=2\n')

set_debug_mode()


# fixtures
@pytest.fixture(scope="module", params=configurations)
def get_configuration(request):
    """Get configurations from the module"""
    return request.param

@pytest.fixture(scope="module")
def configure_authd_server(request):    
    authd_server.start()    
    global monitored_sockets
    monitored_sockets = QueueMonitor(authd_server.queue)
    authd_server.clear()
    yield
    authd_server.shutdown()

@pytest.fixture(scope="function")
def start_authd(request):
    authd_server.clear()

@pytest.fixture(scope="function")
def set_authd_id(request):
    authd_server.agent_id = 101    

@pytest.fixture(scope="function")
def clean_keys(request):   
    truncate_file(CLIENT_KEYS_PATH)
    sleep(1)

@pytest.fixture(scope="function")
def delete_keys(request):   
    os.remove(CLIENT_KEYS_PATH)
    sleep(1)

@pytest.fixture(scope="function")
def set_keys(request):    
    with open(CLIENT_KEYS_PATH, 'w+') as f:
        f.write("100 ubuntu-agent any TopSecret")
    sleep(1)

@pytest.fixture(scope="function")
def clean_logs(request):
    truncate_file(LOG_FILE_PATH)


@pytest.fixture(scope="function")
def restart_agentd(request):
    control_service('stop', daemon="ossec-agentd")
    control_service('start', daemon="ossec-agentd", debug_mode=True)

def wait_notify(line):
    if 'Sending keep alive:' in line:
        return line
    return None 

def wait_enrollment(line):
    if 'Valid key created. Finished.' in line:
        return line
    return None
      
# Tests   
def test_agentd_reconection_enrollment_with_keys(configure_authd_server, start_authd, set_authd_id, set_keys, clean_logs, configure_environment, restart_agentd, get_configuration):
    
    #Clean log to start hearing it
    truncate_file(LOG_FILE_PATH)
    log_monitor = FileMonitor(LOG_FILE_PATH)

    remoted_server = RemotedSimulator(protocol=get_configuration['metadata']['PROTOCOL'], mode='CONTROLED_ACK', client_keys=CLIENT_KEYS_PATH)  
    #hearing on enrollment server    
    authd_server.clear()   
      
    #Wait until Agent is notifing Manager
    try:
        log_monitor.start(timeout=120, callback=wait_notify) 
    except TimeoutError as err:
        remoted_server.stop()
        raise AssertionError("Notify message from agent was never sent!")
    assert "aes" in remoted_server.last_message_ctx, "Incorrect Secure Message"

    #Start rejecting Agent
    remoted_server.set_mode('REJECT') 
    #hearing on enrollment server    
    authd_server.clear()     
    #Wait until Agent asks a new key to enrollment 
    try:    
        log_monitor.start(timeout=180, callback=wait_enrollment)
    except TimeoutError as err:
        remoted_server.stop()
        raise AssertionError("Agent never enrolled after rejecting connection!")

    #Start responding to Agent
    remoted_server.set_mode('CONTROLED_ACK')
    #Wait until Agent is notifing Manager
    try:
        log_monitor.start(timeout=120, callback=wait_notify) 
    except TimeoutError as err:
        remoted_server.stop()
        raise AssertionError("Notify message from agent was never sent!")
    assert "aes" in remoted_server.last_message_ctx, "Incorrect Secure Message"
    
    remoted_server.stop()
   
    return

def test_agentd_reconection_enrollment_no_keys_file(configure_authd_server, start_authd, set_authd_id, delete_keys, clean_logs, configure_environment, restart_agentd, get_configuration):
  
    #start hearing logs
    log_monitor = FileMonitor(LOG_FILE_PATH)

    remoted_server = RemotedSimulator(protocol=get_configuration['metadata']['PROTOCOL'], mode='CONTROLED_ACK', client_keys=CLIENT_KEYS_PATH)  
    #hearing on enrollment server 
    authd_server.clear()   

    #Wait until Agent asks keys for the first time
    try:
        log_monitor.start(timeout=120, callback=wait_enrollment)
    except TimeoutError as err:
        remoted_server.stop()
        raise AssertionError("Agent never enrolled for the first time rejecting connection!")     
    
    #Wait until Agent is notifing Manager
    try:
        log_monitor.start(timeout=120, callback=wait_notify) 
    except TimeoutError as err:
        remoted_server.stop()
        raise AssertionError("Notify message from agent was never sent!")     
    assert "aes" in remoted_server.last_message_ctx, "Incorrect Secure Message"

    #Start rejecting Agent
    remoted_server.set_mode('REJECT') 
    #hearing on enrollment server    
    authd_server.clear()     
    #Wait until Agent asks a new key to enrollment 
    try:    
        log_monitor.start(timeout=180, callback=wait_enrollment)
    except TimeoutError as err:
        remoted_server.stop()
        raise AssertionError("Agent never enrolled after rejecting connection!")

    #Start responding to Agent
    remoted_server.set_mode('CONTROLED_ACK')
    #Wait until Agent is notifing Manager
    try:
        log_monitor.start(timeout=120, callback=wait_notify)
    except TimeoutError as err:
        remoted_server.stop()
        raise AssertionError("Notify message from agent was never sent!")
    assert "aes" in remoted_server.last_message_ctx, "Incorrect Secure Message"

    remoted_server.stop()

    return

def test_agentd_reconection_enrollment_no_keys(configure_authd_server, start_authd, set_authd_id, clean_keys, clean_logs, configure_environment, restart_agentd, get_configuration):
  
    #start hearing logs
    log_monitor = FileMonitor(LOG_FILE_PATH)

    remoted_server = RemotedSimulator(protocol=get_configuration['metadata']['PROTOCOL'], mode='CONTROLED_ACK', client_keys=CLIENT_KEYS_PATH)  
    #hearing on enrollment server 
    authd_server.clear()   

    #Wait until Agent asks keys for the first time
    try:
        log_monitor.start(timeout=120, callback=wait_enrollment)
    except TimeoutError as err:
        remoted_server.stop()
        raise AssertionError("Agent never enrolled for the first time rejecting connection!")     
    
    #Wait until Agent is notifing Manager
    try:
        log_monitor.start(timeout=120, callback=wait_notify) 
    except TimeoutError as err:
        remoted_server.stop()
        raise AssertionError("Notify message from agent was never sent!")     
    assert remoted_server.last_message_ctx == "by_id 101 aes", "Incorrect Secure Message"

    #Start rejecting Agent
    remoted_server.set_mode('REJECT') 
    #hearing on enrollment server    
    authd_server.clear()     
    #Wait until Agent asks a new key to enrollment 
    try:    
        log_monitor.start(timeout=180, callback=wait_enrollment)
    except TimeoutError as err:
        remoted_server.stop()
        raise AssertionError("Agent never enrolled after rejecting connection!")

    #Start responding to Agent
    remoted_server.set_mode('CONTROLED_ACK')
    #Wait until Agent is notifing Manager
    try:
        log_monitor.start(timeout=120, callback=wait_notify)
    except TimeoutError as err:
        remoted_server.stop()
        raise AssertionError("Notify message from agent was never sent!")
    assert remoted_server.last_message_ctx == "by_id 102 aes", "Incorrect Secure Message"

    remoted_server.stop()

    return
