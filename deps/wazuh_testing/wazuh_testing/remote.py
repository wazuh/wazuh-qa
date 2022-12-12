# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import re
import socket
import ipaddress
import subprocess as sb
import time
import multiprocessing
import pytest
import wazuh_testing.tools.agent_simulator as ag
from wazuh_testing import UDP, TCP, ARCHIVES_LOG_PATH, LOG_FILE_PATH, QUEUE_SOCKETS_PATH, WAZUH_PATH
from wazuh_testing.tools.file import bind_unix_socket, truncate_file
from wazuh_testing.tools.monitoring import FileMonitor, make_callback, ManInTheMiddle, QueueMonitor, \
    REMOTED_DETECTOR_PREFIX
from wazuh_testing.tools.services import control_service


REMOTED_GLOBAL_TIMEOUT = 10
SYNC_FILES_TIMEOUT = 10
EXAMPLE_MESSAGE_EVENT = '1:/root/test.log:Feb 23 17:18:20 35-u20-manager4 sshd[40657]: Accepted publickey for root' \
                        ' from 192.168.0.5 port 48044 ssh2: RSA SHA256:IZT11YXRZoZfuGlj/K/t3tT8OdolV58hcCOJFZLIW2Y'
EXAMPLE_INVALID_USER_LOG_EVENT = 'Feb  4 16:39:29 ip-10-142-167-43 sshd[6787]: ' \
                                 'Invalid user single-log-w-header from 127.0.0.1 port 41328'
EXAMPLE_VALID_USER_LOG_EVENT = '2021-03-04T02:16:16.998693-05:00 centos-8 su - - [timeQuality tzKnown="1" ' \
                               'isSynced="0"] pam_unix(su:session): session opened for user wazuh_qa by (uid=0)'
EXAMPLE_MESSAGE_PATTERN = 'Accepted publickey for root from 192.168.0.5 port 48044'
ACTIVE_RESPONSE_EXAMPLE_COMMAND = 'dummy-ar admin 1.1.1.1 1.1 44 (any-agent) any->/testing/testing.txt - -'
QUEUE_SOCKET_PATH = os.path.join(QUEUE_SOCKETS_PATH, 'queue')

DEFAULT_TESTING_GROUP_NAME = 'testing_group'

data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')


def new_agent_group(group_name=DEFAULT_TESTING_GROUP_NAME, configuration_file='agent.conf'):
    """Create a new agent group for testing purpose, must be run only on Managers."""

    sb.run([f"{WAZUH_PATH}/bin/agent_groups", "-q", "-a", "-g", group_name])

    agent_conf_path = os.path.join(data_path, configuration_file)

    with open(f"{WAZUH_PATH}/etc/shared/{group_name}/agent.conf", "w") as agent_conf_file:
        with open(agent_conf_path, 'r') as configuration:
            agent_conf_file.write(configuration.read())


def remove_agent_group(group_name):
    sb.run([f"{WAZUH_PATH}/bin/agent_groups", "-q", "-r", "-g", group_name])


def add_agent_to_group(group_name, agent_id):
    sb.run([f"{WAZUH_PATH}/bin/agent_groups", "-q", "-a", "-i", agent_id, "-g", group_name])


def callback_detect_syslog_allowed_ips(syslog_ips):
    """Create a callback to detect syslog allowed-ips.

    Args:
        syslog_ips (str): syslog allowed-ips.

    Returns:
        callable: callback to detect this event.
    """

    msg = fr"Remote syslog allowed from: \'{syslog_ips}\'"
    return make_callback(pattern=msg, prefix=REMOTED_DETECTOR_PREFIX)


def callback_detect_syslog_denied_ips(syslog_ips):
    """Create a callback to detect syslog denied-ips.

    Args:
        syslog_ips (str): syslog denied-ips.

    Returns:
        callable: callback to detect this event.
    """
    msg = fr"Message from \'{syslog_ips}\' not allowed. Cannot find the ID of the agent."
    return make_callback(pattern=msg, prefix=REMOTED_DETECTOR_PREFIX)


def callback_invalid_value(option, value):
    """Create a callback to detect invalid values in ossec.conf file.

    Args:
        option (str): Wazuh manager configuration option.
        value (str): Value of the configuration option.

    Returns:
        callable: callback to detect this event.
    """
    msg = fr"ERROR: \(\d+\): Invalid value for element '{option}': {value}."
    return make_callback(pattern=msg, prefix=REMOTED_DETECTOR_PREFIX)


def callback_error_invalid_port(port):
    """Create a callback to detect invalid port.callback_detect_remoted_started

    Args:
        port (str): Wazuh manager port.

    Returns:
        callable: callback to detect this event.
    """
    msg = fr"ERROR: \(\d+\): Invalid port number: '{port}'."
    return make_callback(pattern=msg, prefix=REMOTED_DETECTOR_PREFIX)


def callback_ignored_invalid_protocol(protocol):
    """Create a callback to detect invalid protocol.

    Args:
        protocol (str): Wazuh manager protocol.

    Returns:
        callable: callback to detect this event.
    """
    msg = fr"WARNING: \(\d+\): Ignored invalid value '{protocol}' for 'protocol'"
    return make_callback(pattern=msg, prefix=REMOTED_DETECTOR_PREFIX)


def callback_error_getting_protocol():
    """Create a callback to detect if warning message is created when no valid protocol is provided.

    Returns:
        callable: callback to detect this event.
    """
    msg = r"WARNING: \(\d+\): Error getting protocol. Default value \(TCP\) will be used."
    return make_callback(pattern=msg, prefix=REMOTED_DETECTOR_PREFIX)


def callback_warning_syslog_tcp_udp():
    """Create a callback to detect if warning message is created when multiple protocol are provided using syslog.

    Returns:
        callable: callback to detect this event.
    """
    msg = r"WARNING: \(\d+\): Only secure connection supports TCP and UDP at the same time. " \
          r"Default value \(TCP\) will be used."

    return make_callback(pattern=msg, prefix=REMOTED_DETECTOR_PREFIX)


def callback_warning_secure_ipv6():
    """Create a callback to detect if warning message is created when ipv6 is used along with secure connection.

    Returns:
        callable: callback to detect this event.
    """
    msg = r"WARNING: \(\d+\): Secure connection does not support IPv6. IPv4 will be used instead."
    return make_callback(pattern=msg, prefix=REMOTED_DETECTOR_PREFIX)


def callback_error_bind_port():
    """Create a callback to detect if critical error is created when invalid local ip value is provided.

    Returns:
        callable: callback to detect this event.
    """
    msg = r"CRITICAL: \(\d+\): Unable to Bind port '1514' due to \[\(\d+\)\-\(Cannot assign requested address\)\]"
    return make_callback(pattern=msg, prefix=REMOTED_DETECTOR_PREFIX)


def callback_error_queue_size_syslog():
    """Create a callback to detect if error is created when queue_size is used along with syslog connection.

    Returns:
        callable: callback to detect this event.
    """
    msg = r"ERROR: Invalid option \<queue_size\> for Syslog remote connection."
    return make_callback(pattern=msg, prefix=REMOTED_DETECTOR_PREFIX)


def callback_queue_size_too_big():
    """Create a callback to detect if warning message is created when queue_size is too big.

    Returns:
        callable: callback to detect this event.
    """
    msg = r"WARNING: Queue size is very high. The application may run out of memory."
    return make_callback(pattern=msg, prefix=REMOTED_DETECTOR_PREFIX)


def callback_error_invalid_ip(ip):
    """Create a callback to detect if error is created when invalid local ip value is provided.

    Args:
        ip (str): IP address.

    Returns:
        callable: callback to detect this event.
    """
    msg = fr"ERROR: \(\d+\): Invalid ip address: '{ip}'."
    return make_callback(pattern=msg, prefix=REMOTED_DETECTOR_PREFIX)


def callback_info_no_allowed_ips():
    """Create a callback to detect if error message is syslog server is disabled when no allowed ips is provided.

    Returns:
        callable: callback to detect this event.
    """
    msg = r"INFO: \(\d+\): IP or network must be present in syslog access list \(allowed-ips\). "
    msg += "Syslog server disabled."
    return make_callback(pattern=msg, prefix=REMOTED_DETECTOR_PREFIX)


def get_protocols(all_protocols):
    """Create a pair of arrays with valid protocols (TCP and UDP) in element 0 and invalid protocols in element 1.

    Args:
        all_protocols (list): List of strings with valid and invalid protocols.

    Returns:
        array: Array with valid protocol list in element 0 and invalid protocols in element 1.
    """
    valid_protocols = []
    invalid_protocols = []
    for protocol in all_protocols:
        if protocol == 'UDP' or protocol == 'TCP':
            valid_protocols.append(protocol)
        else:
            invalid_protocols.append(protocol)
    return [valid_protocols, invalid_protocols]


def callback_active_response_received(ar_message):
    msg = fr"DEBUG: Active response request received: {ar_message}"
    return make_callback(pattern=msg, prefix=REMOTED_DETECTOR_PREFIX, escape=True)


def callback_active_response_sent(ar_message):
    msg = fr"DEBUG: Active response sent: #!-execd {ar_message[26:]}"
    return make_callback(pattern=msg, prefix=REMOTED_DETECTOR_PREFIX, escape=True)


def callback_start_up(agent_name, agent_ip='127.0.0.1'):
    msg = fr"DEBUG: Agent {agent_name} sent HC_STARTUP from '{agent_ip}'"
    return make_callback(pattern=msg, prefix=REMOTED_DETECTOR_PREFIX, escape=True)


def callback_detect_remoted_started(port, protocol, connection_type="secure"):
    """Create a callback to detect if remoted was correctly started.

    wazuh-remoted logs if it has correctly started for each connection type, the port and the protocol in the ossec.log

    Args:
        port (int): port configured for wazuh-remoted.
        protocol (str): protocol configured for wazuh-remoted. It can be UDP, TCP or both options at the same time.
        connection_type (str): it can be secure or syslog.

    Returns:
        callable: callback to detect this event.
    """
    protocol_array = protocol.split(',')
    protocol_array.sort()

    protocol_string = protocol

    if len(protocol_array) > 1:
        protocol_string = protocol_array[0] + ',' + protocol_array[1]

    msg = fr"Started \(pid: \d+\). Listening on port {port}\/{protocol_string.upper()} \({connection_type}\)."
    return make_callback(pattern=msg, prefix=REMOTED_DETECTOR_PREFIX)


def callback_detect_syslog_event(message):
    """Create a callback to detect the syslog messages in the archives.log.

    Args:
        message (str): syslog message sent through the socket.

    Returns:
        callable: callback to detect this event.
    """
    return make_callback(pattern=message, prefix=r".*->\d+\.\d+\.\d+\.\d+\s", escape=True)


def callback_detect_example_archives_event():
    """Create a callback to detect the example message in the archives.log

    Returns:
        callable: callback to detect this event
    """
    return make_callback(pattern=fr".*{EXAMPLE_MESSAGE_PATTERN}.*", prefix=None)


def send_syslog_message(message, port, protocol, manager_address="127.0.0.1"):
    """Send a message to the syslog server of wazuh-remoted.

    Args:
        message (str): string to send as a syslog event.
        protocol (str): it can be UDP or TCP.
        port (int): port where the manager has bound the remoted port.
        manager_address (str): address of the manager.

    Raises:
        ConnectionRefusedError: if there's a problem while sending messages to the manager.
    """
    ip = ipaddress.ip_address(manager_address)
    if protocol.upper() == UDP:
        if isinstance(ip, ipaddress.IPv4Address):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        elif isinstance(ip, ipaddress.IPv6Address):
            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    else:
        if isinstance(ip, ipaddress.IPv4Address):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        elif isinstance(ip, ipaddress.IPv6Address):
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)

    if not message.endswith("\n"):
        message += "\n"

    sock.connect((manager_address, port))
    sock.send(message.encode())
    sock.close()


def create_archives_log_monitor():
    """Create a FileMonitor for the archives.log file.

    Returns:
        FileMonitor: object to monitor the archives.log.
    """
    # Reset archives.log and start a new monitor
    truncate_file(ARCHIVES_LOG_PATH)
    wazuh_archives_log_monitor = FileMonitor(ARCHIVES_LOG_PATH)

    return wazuh_archives_log_monitor


def detect_archives_log_event(archives_monitor, callback, error_message=None, update_position=True, timeout=5):
    """Monitor the archives.log to detect a certain event.

    Args:
        archives_monitor (FileMonitor): FileMonitor bound to the archives.log.
        callback (callable): lambda function used to detect the event.
        error_message (str): String used as human readable error if the event is not found.
        update_position (bool): bool value used to update the position of `archives_monitor`.
        timeout (int): maximum time in seconds to expect the event.

    Raises:
        TimeoutError: if the event is not found in the file.
    """
    if error_message is None:
        error_message = 'Could not detect the expected event in archives.log'

    archives_monitor.start(timeout=timeout, update_position=update_position, callback=callback,
                           error_message=error_message)


def check_syslog_event(wazuh_archives_log_monitor, message, port, protocol, timeout=10):
    """Check if a syslog event is properly received by the manager.

    Args:
        wazuh_archives_log_monitor (FileMonitor): FileMonitor object to monitor the archives.log.
        message (str): Message sent for syslog that must appear in the archives.log.
        protocol (str): it can be UDP or TCP.
        port (int): port where the manager has bound the remoted port.
        timeout (int): maximum time to expect the syslog event in the log file.
    """
    send_syslog_message(message, port, protocol)

    # Syslog events may contain a PRI header at the beginning of the message <1>. If wazuh-remoted receives a message
    # with this header, it parses the message and removes the header. That's why we remove the header to search the
    # event in the archives.log. More info about PRI headers at: https://tools.ietf.org/html/rfc3164#section-4.1.1
    parsed_msg = re.sub(r"<.+>", '', message)

    for msg in parsed_msg.split("\n"):
        detect_archives_log_event(archives_monitor=wazuh_archives_log_monitor,
                                  callback=callback_detect_syslog_event(msg),
                                  update_position=False,
                                  timeout=timeout,
                                  error_message="Syslog message wasn't received or took too much time.")


def send_ping_pong_messages(protocol, manager_address, port):
    """Send the ping message to the manager.

    This message is the first of many between the manager and the agents. It is used to check if both of them are ready
    to send and receive other messages.

    Args:
        protocol (str): it can be UDP or TCP.
        manager_address (str): address of the manager. IP and hostname are valid options.
        port (int): port where the manager has bound the remoted port.

    Returns:
        bytes: returns the #pong message from the manager.

    Raises:
        ConnectionRefusedError: if there's a problem while sending messages to the manager.
    """
    protocol = protocol.upper()
    if protocol == UDP:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ping_msg = b'#ping'
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        msg = '#ping'
        msg_size = len(bytearray(msg, 'utf-8'))
        # Since the message size's is represented as an unsigned int32, you need to use 4 bytes to represent it
        ping_msg = msg_size.to_bytes(4, 'little') + msg.encode()

    sock.connect((manager_address, port))
    sock.send(ping_msg)
    response = sock.recv(len(ping_msg))
    sock.close()
    return response if protocol == UDP else response[-5:]


def check_remoted_log_event(wazuh_log_monitor, callback_pattern, error_message='', update_position=False,
                            timeout=REMOTED_GLOBAL_TIMEOUT):
    """Allow to monitor the ossec.log file and search for a remoted event.

    Args:
        wazuh_log_monitor (FileMonitor): FileMonitor object to monitor the Wazuh log.
        callback_pattern (str): Regex pattern to search in ossec.log.
        error_message (str): Message error to show in case that the callback pattern is not found in the expected time.
        update_position (boolean): True to search from the last line of the log file, False to search in the complete
                                   log file.
        timeout (int): Maximum time in seconds for event search in log.

    Raises:
        TimeoutError: if callback pattern is not found in ossec.log in the expected time.
    """
    wazuh_log_monitor.start(
        timeout=timeout,
        update_position=update_position,
        callback=make_callback(callback_pattern, REMOTED_DETECTOR_PREFIX),
        error_message=error_message
    )


def check_tcp_connection_established_log(wazuh_log_monitor, update_position=False, ip_address='127.0.0.1'):
    """Allow to detect events of new incoming TCP connections in the ossec.log.

    Args:
        wazuh_log_monitor (FileMonitor): FileMonitor object to monitor the Wazuh log.
        update_position (boolean): True to search from the last line of the log file, False to search in the complete.
                                   log file.
        ip_address (str): IP address of incoming connection.

    Raises:
        TimeoutError: if callback pattern is not found in ossec.log in the expected time.
    """
    callback_pattern = f".*New TCP connection at {ip_address}.*"
    error_message = f"Could not find the log with the following pattern {callback_pattern}"

    check_remoted_log_event(wazuh_log_monitor, callback_pattern, error_message, update_position)


def wait_to_remoted_key_update(wazuh_log_monitor):
    """Allow to detect when remoted has updated its info with the client.keys.

    This is necessary for remoted to correctly recognize the agent, and to be able to decrypt its messages.

    The reload time is editable in the internal_options.conf and defaults to 10 seconds.

    >> remoted.keyupdate_interval=10

    It is recommended to set this time to 5 or less for testing.

    Args:
        wazuh_log_monitor (FileMonitor): FileMonitor object to monitor the Wazuh log.

    Raises:
        TimeoutError: if could not find the remoted key loading log.
    """
    # We have to make sure that remoted has correctly loaded the client key agent info. The log is truncated to
    # ensure that the information has been loaded after the agent has been registered.
    truncate_file(LOG_FILE_PATH)

    callback_pattern = '.*rem_keyupdate_main().*Checking for keys file changes.'
    error_message = 'Could not find the remoted key loading log'

    check_remoted_log_event(wazuh_log_monitor, callback_pattern, error_message, timeout=20)


def wait_to_remoted_update_groups(wazuh_log_monitor):
    """Allow to detect when remoted has reloaded its groups and multigroups.

    This is necessary for remoted to find shared group files to send to agents.

    The reload time is editable in the internal_options.conf and defaults to 10 seconds.

    >> remoted.shared_reload=10

    Args:
        wazuh_log_monitor (FileMonitor): FileMonitor object to monitor the Wazuh log.

    Raises:
        TimeoutError: if could not find the remoted key loading log.
    """
    # We have to make sure that remoted has correctly reloaded its groups and multigroups.
    # The log is truncated to ensure that the information has been loaded after the agent has been registered.
    truncate_file(LOG_FILE_PATH)

    callback_pattern = '.*c_files().*End updating shared files sums.'
    error_message = 'Could not find the groups reload log'

    check_remoted_log_event(wazuh_log_monitor, callback_pattern, error_message, timeout=SYNC_FILES_TIMEOUT)


def send_agent_event(wazuh_log_monitor, message=EXAMPLE_MESSAGE_EVENT, protocol=TCP, manager_address='127.0.0.1',
                     manager_port=1514, agent_os='debian7', agent_version='4.2.0', disable_all_modules=True):
    """Allow to create a new simulated agent and send a message to the manager.

    Args:
        wazuh_log_monitor (FileMonitor): FileMonitor object to monitor the Wazuh log.
        message (str): Raw event to send to the manager.
        protocol (str): it can be UDP or TCP.
        manager_address (str): Manager IP address.
        manager_port (str): Port used by remoted in the manager.
        agent_os (str): Agent operating system. The OS must belong to the agent simulator's list of allowed agents.
        agent_version (str): Agent version.
        disable_all_modules (boolean): True to disable all agent modules, False otherwise.

    Returns:
        tuple(Agent, Sender): agent and sender objects.
    """
    # Create an agent with agent simulator
    agent = ag.Agent(manager_address=manager_address, os=agent_os, version=agent_version,
                     disable_all_modules=disable_all_modules)

    # Wait until remoted has loaded the new agent key
    wait_to_remoted_key_update(wazuh_log_monitor)

    # Build the event message and send it to the manager as an agent event
    event = agent.create_event(message)

    # Send the event to the manager
    sender = ag.Sender(manager_address=manager_address, manager_port=manager_port, protocol=protocol)
    sender.send_event(event)

    return agent, sender


def check_queue_socket_event(raw_events=EXAMPLE_MESSAGE_PATTERN, timeout=30, update_position=False):
    """Allow searching for an expected event in the queue socket.

    Args:
        raw_events (str or list<str>): Pattern/s regex to be found in the socket.
        timeout (int): Maximum search time of the event in the socket. Default is 30 to allow enough time for the
                       other thread to send messages.
        update_position (boolean): True to search in the entire queue, False to search in the current position of the
                                   queue.

    Raises:
        TimeoutError: if could not find the pattern regex event in the queue socket.
    """

    # Do not delete. Function required for MITM to work
    def intercept_socket_data(data):
        return data

    error_message = 'Could not find the expected event in queue socket'

    # Get the event list
    event_list = [raw_events] if isinstance(raw_events, str) else raw_events

    # Stop analysisd daemon to free the socket. Important note: control_service(stop) deletes the daemon sockets.
    control_service('stop', daemon='wazuh-analysisd')

    # Create queue socket if it does not exist.
    bind_unix_socket(QUEUE_SOCKET_PATH, UDP)

    # Intercept queue sockets events
    mitm = ManInTheMiddle(address=QUEUE_SOCKET_PATH, family='AF_UNIX', connection_protocol=UDP,
                          func=intercept_socket_data)
    mitm.start()

    # Monitor MITM queue
    socket_monitor = QueueMonitor(mitm.queue)

    try:
        # Start socket monitoring
        for event in event_list:
            socket_monitor.start(timeout=timeout, callback=make_callback(event, '.*'),
                                 error_message=error_message, update_position=update_position)
    finally:
        mitm.shutdown()
        control_service('start', daemon='wazuh-analysisd')


def check_agent_received_message(agent, search_pattern, timeout=5, update_position=True, error_message='',
                                 escape=False):
    """Allow to monitor the agent received messages to search a pattern regex.

    Args:
        agent (Agent): Agent to monitor the received messages in its Queue.
        search_pattern (str): Regex to search in agent received messages.
        timeout (int): Maximum time in seconds to search the event.
        update_position (boolean): True to search in the entire queue, False to search in the current position of the
                                   queue.
        error_message (string): Message to explain the exception.
        escape (bool): Flag to escape special characters in the pattern

    Raises:
        TimeoutError: if search pattern is not found in agent received messages queue in the expected time.

    """
    queue_monitor = QueueMonitor(agent.rcv_msg_queue)
    queue_monitor.start(timeout=timeout, callback=make_callback(search_pattern, '.*', escape),
                        update_position=update_position, error_message=error_message)


def check_push_shared_config(agent, sender, injector=None):
    """Allow to check if the manager sends the shared configuration to agents through remoted.

    First, check if the default group configuration file is completely pushed (up message, configuration
    and close message). Then add the agent to a new group and check if the new configuration is pushed.
    Also it checks that the same config isn't pushed two times.

    Args:
        agent (Agent): Agent to check if the shared configuration is pushed.
        sender (Sender): Sender object associated to the agent and used to send messages to the manager.
        injector (Injector): Injector associated to the agent and sender. If None, a new one will be created.
    Raises:
        TimeoutError: If agent does not receive the manager ACK message in the expected time.
    """

    # Activate receives_messages modules in simulated agent.
    def keep_alive_until_group_configuration_sent(sender, interval=1, timeout=20):
        for i in range(timeout):
            sender.send_event(agent.keep_alive_event)
            time.sleep(interval)

    agent.set_module_status('receive_messages', 'enabled')

    # Run injector with only receive messages module enabled
    stop_injector = False

    if injector is None:
        injector = ag.Injector(sender, agent)
        injector.run()
        stop_injector = True

    try:
        wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

        # Wait until remoted has loaded the new agent key
        wait_to_remoted_key_update(wazuh_log_monitor)

        # Send the start-up message
        sender.send_event(agent.startup_msg)

        log_callback = callback_start_up(agent.name)
        wazuh_log_monitor.start(timeout=REMOTED_GLOBAL_TIMEOUT, callback=log_callback,
                                error_message='The start up message has not been found in the logs')

        wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

        sender.send_event(agent.keep_alive_event)

        # Check up file (push start) message
        check_agent_received_message(agent, r'#!-up file \w+ merged.mg', timeout=10,
                                     error_message="initial up file message not received")

        # Check agent.conf message
        check_agent_received_message(agent, '#default', timeout=10,
                                     error_message="agent.conf message not received")
        # Check close file (push end) message
        check_agent_received_message(agent, 'close', timeout=35,
                                     error_message="initial close message not received")

        sender.send_event(agent.keep_alive_event)

        # Check that push message doesn't appear again
        with pytest.raises(TimeoutError):
            check_agent_received_message(agent, r'#!-up file \w+ merged.mg', timeout=5)
            raise AssertionError("Same shared configuration pushed twice!")

        # Add agent to group and check if the configuration is pushed.
        add_agent_to_group(DEFAULT_TESTING_GROUP_NAME, agent.id)

        # Wait until remoted has reloaded its groups and multigroups
        wait_to_remoted_update_groups(wazuh_log_monitor)

        keep_alive_agent = multiprocessing.Process(target=keep_alive_until_group_configuration_sent,
                                                   args=(sender,))
        keep_alive_agent.start()

        log_callback = make_callback(pattern=".*End sending file '.+' to agent '\d+'\.", prefix='.*wazuh-remoted.*')
        log_monitor = FileMonitor(LOG_FILE_PATH)
        log_monitor.start(timeout=REMOTED_GLOBAL_TIMEOUT, callback=log_callback,
                          error_message="New shared configuration was not sent")
        check_agent_received_message(agent, '#!-up file .* merged.mg', timeout=REMOTED_GLOBAL_TIMEOUT,
                                     error_message="New group shared config not received")

    finally:
        if stop_injector:
            injector.stop_receive()
            keep_alive_agent.terminate()
