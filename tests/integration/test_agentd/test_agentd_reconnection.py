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
from datetime import datetime, timedelta
# Marks

pytestmark = [pytest.mark.linux, pytest.mark.win32, pytest.mark.tier(level=0), pytest.mark.agent]

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

remoted_server = None

def teardown():
    global remoted_server
    if remoted_server != None:
        remoted_server.stop()

def set_debug_mode():    
    if platform.system() == 'win32' or platform.system() == 'Windows':
        local_int_conf_path=os.path.join(WAZUH_PATH, 'local_internal_options.conf')
        debug_line = 'windows.debug=2\n'
    else:
        local_int_conf_path=os.path.join(WAZUH_PATH,'etc', 'local_internal_options.conf')
        debug_line = 'agent.debug=2\n'

    with  open(local_int_conf_path, 'r') as local_file_read:
        lines = local_file_read.readlines()
        for line in lines: 
            if line == debug_line:
                return
    with  open(local_int_conf_path, 'a') as local_file_write:
        local_file_write.write('\n'+debug_line)

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
    authd_server.set_mode("ACCEPT")
    authd_server.clear()

@pytest.fixture(scope="function")
def stop_authd(request):
    authd_server.set_mode("REJECT")

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

def wait_notify(line):
    if 'Sending keep alive:' in line:
        return line
    return None 

def wait_enrollment(line):
    if 'Valid key created. Finished.' in line:
        return line
    return None

def wait_enrollment_try(line):
    if 'Starting enrollment process' in line:
        return line
    return None

def search_error_messages():
    with open(LOG_FILE_PATH , 'r') as log_file:
        lines = log_file.readlines()
        for line in lines:
            if f"ERROR:" in line:
                return line
    return None
      
# Tests 
"""
This test covers the scenario of Agent starting with keys,
when misses comunication with Remoted and a new enrollment is sent to Authd.
"""
def test_agentd_reconection_enrollment_with_keys(configure_authd_server, start_authd, set_authd_id, set_keys, configure_environment, get_configuration):
    global remoted_server
    
    #Stop target Agent
    control_service('stop')
    #Clean logs
    truncate_file(LOG_FILE_PATH)    
    #Start target Agent
    control_service('start')

    #Start hearing logs
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
        raise AssertionError("Notify message from agent was never sent!")
    assert "aes" in remoted_server.last_message_ctx, "Incorrect Secure Message"
        
    return

"""
This test covers the scenario of Agent starting without client.keys file
and an enrollment is sent to Authd to start comunicating with Remoted
"""
def test_agentd_reconection_enrollment_no_keys_file(configure_authd_server, start_authd, set_authd_id, delete_keys, configure_environment, get_configuration):
    global remoted_server

    #Stop target Agent
    control_service('stop')
    #Clean logs
    truncate_file(LOG_FILE_PATH)    
    #Start target Agent
    control_service('start')
    
    #start hearing logs
    log_monitor = FileMonitor(LOG_FILE_PATH)

    remoted_server = RemotedSimulator(protocol=get_configuration['metadata']['PROTOCOL'], mode='CONTROLED_ACK', client_keys=CLIENT_KEYS_PATH)  
    #hearing on enrollment server 
    authd_server.clear()   

    #Wait until Agent asks keys for the first time
    try:
        log_monitor.start(timeout=120, callback=wait_enrollment)
    except TimeoutError as err:
        raise AssertionError("Agent never enrolled for the first time rejecting connection!")     
    
    #Wait until Agent is notifing Manager
    try:
        log_monitor.start(timeout=120, callback=wait_notify) 
    except TimeoutError as err:
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
        raise AssertionError("Agent never enrolled after rejecting connection!")

    #Start responding to Agent
    remoted_server.set_mode('CONTROLED_ACK')
    #Wait until Agent is notifing Manager
    try:
        log_monitor.start(timeout=120, callback=wait_notify)
    except TimeoutError as err:
        raise AssertionError("Notify message from agent was never sent!")
    assert "aes" in remoted_server.last_message_ctx, "Incorrect Secure Message"

    return

"""
This test covers the scenario of Agent starting without keys in client.keys file
and an enrollment is sent to Authd to start comunicating with Remoted
"""
def test_agentd_reconection_enrollment_no_keys(configure_authd_server, start_authd, set_authd_id, clean_keys, configure_environment, get_configuration):
    global remoted_server
    
    #Stop target Agent
    control_service('stop')
    #Clean logs
    truncate_file(LOG_FILE_PATH)    
    #Start target Agent
    control_service('start')
    
    #start hearing logs
    log_monitor = FileMonitor(LOG_FILE_PATH)

    remoted_server = RemotedSimulator(protocol=get_configuration['metadata']['PROTOCOL'], mode='CONTROLED_ACK', client_keys=CLIENT_KEYS_PATH)  
    #hearing on enrollment server 
    authd_server.clear()   

    #Wait until Agent asks keys for the first time
    try:
        log_monitor.start(timeout=120, callback=wait_enrollment)
    except TimeoutError as err:
        raise AssertionError("Agent never enrolled for the first time rejecting connection!")     
    
    #Wait until Agent is notifing Manager
    try:
        log_monitor.start(timeout=120, callback=wait_notify) 
    except TimeoutError as err:
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
        raise AssertionError("Agent never enrolled after rejecting connection!")

    #Start responding to Agent
    remoted_server.set_mode('CONTROLED_ACK')
    #Wait until Agent is notifing Manager
    try:
        log_monitor.start(timeout=120, callback=wait_notify)
    except TimeoutError as err:
        raise AssertionError("Notify message from agent was never sent!")
    assert "aes" in remoted_server.last_message_ctx, "Incorrect Secure Message"

    return

"""
This test covers and check the scenario of Agent starting without keys
and multiple retries are required until the new key is obtained to start comunicating with Remoted
"""
def test_agentd_initial_enrollment_retries(configure_authd_server, stop_authd, set_authd_id, clean_keys, configure_environment, get_configuration):
    global remoted_server
    
    #Stop target Agent
    control_service('stop')
    #Clean logs
    truncate_file(LOG_FILE_PATH)    
    #Start whole Agent service to check other daemons status after initialization
    control_service('start')
    
    remoted_server = RemotedSimulator(protocol=get_configuration['metadata']['PROTOCOL'], mode='CONTROLED_ACK', client_keys=CLIENT_KEYS_PATH)  
    
    #Start hearing logs    
    log_monitor = FileMonitor(LOG_FILE_PATH)

    start_time = datetime.now()
    #Check for unsuccesful enrollment retries in Agentd initialization
    retries = 0
    while retries < 4:
        retries += 1
        try:
            log_monitor.start(timeout=retries*5+20, callback=wait_enrollment_try) 
        except TimeoutError as err:
            raise AssertionError("Enrollment retry was not sent!")    
    stop_time = datetime.now()
    expected_time = start_time + timedelta(seconds=retries*5-2)  
    #Check if delay was aplied   
    assert stop_time > expected_time, "Retries to quick"

    #Enable authd
    authd_server.clear()
    authd_server.set_mode("ACCEPT")
    #Wait succesfull enrollment
    try:
        log_monitor.start(timeout=70, callback=wait_enrollment) 
    except TimeoutError as err:
        raise AssertionError("No succesful enrollment after reties!")    
    
    #Wait until Agent is notifing Manager
    try:
        log_monitor.start(timeout=120, callback=wait_notify) 
    except TimeoutError as err:
        raise AssertionError("Notify message from agent was never sent!")
    assert "aes" in remoted_server.last_message_ctx, "Incorrect Secure Message"

    #Check if no Wazuh module stoped due to Agentd Initialization
    with open(LOG_FILE_PATH) as log_file:
        log_lines = log_file.read().splitlines() 
        for line in log_lines:
            if "Unable to access queue:" in line:
                raise AssertionError("A Wazuh module stoped because of Agentd initialization!")
   
    return

"""
This test covers and check the scenario of Agent starting with keys
but Remoted is not reachable during some seconds and multiple connection retries are required previous requesting a new enrollment
"""
def test_agentd_connection_retries_pre_enrollment(configure_authd_server, stop_authd, set_keys, configure_environment, get_configuration):
    global remoted_server
    REMOTED_KEYS_SYNC_TIME = 10

    #Start Remoted mock
    remoted_server = RemotedSimulator(protocol=get_configuration['metadata']['PROTOCOL'], client_keys=CLIENT_KEYS_PATH)  

    #Clean logs
    truncate_file(LOG_FILE_PATH)  
    
    #Start target Agentd
    control_service('restart')

    #Start hearing logs    
    log_monitor = FileMonitor(LOG_FILE_PATH)

    #Simulate time of Remoted to synchronize keys by waiting previous to start responding
    sleep(REMOTED_KEYS_SYNC_TIME)
    remoted_server.set_mode('CONTROLED_ACK')

    #Check Agentd is finally comunicating
    try:
        log_monitor.start(timeout=120, callback=wait_notify) 
    except TimeoutError as err:
        raise AssertionError("Notify message from agent was never sent!")

    log_errors = search_error_messages()
    assert log_errors == None, "Error found in logs: "+log_errors

    return
