# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import subprocess
import sys
import time
from subprocess import check_call

import psutil

from wazuh_testing.tools import WAZUH_PATH, get_service, WAZUH_SOCKETS, QUEUE_DB_PATH, WAZUH_OPTIONAL_SOCKETS
from wazuh_testing.tools.configuration import write_wazuh_conf


def restart_wazuh_daemon(daemon):
    """
    Restarts a Wazuh daemon.

    Use this function to avoid restarting the whole service and all of its daemons.

    Args:
        daemon (str): Name of the executable file of the daemon in /var/ossec/bin
    """
    for proc in psutil.process_iter(attrs=['name']):
        if proc.name() == daemon:
            proc.terminate()

    daemon_path = os.path.join(WAZUH_PATH, 'bin')
    check_call([f'{daemon_path}/{daemon}'])


def restart_wazuh_with_new_conf(new_conf, daemon='wazuh-syscheckd'):
    """
    Restart Wazuh service applying a new ossec.conf

    Args:
        new_conf ( ET.ElementTree) : New config file.
        daemon (str, optional): Daemon to restart when applying the configuration.
    """
    write_wazuh_conf(new_conf)
    control_service('restart', daemon=daemon)


def delete_sockets(path=None):
    """Delete a list of Wazuh socket files or all of them if None is specified.

    Args:
        path (list, optional): Absolute socket path. Default `None`
    """
    try:
        if path is None:
            path = os.path.join(WAZUH_PATH, 'queue', 'ossec')
            for file in os.listdir(path):
                os.remove(os.path.join(path, file))
            if os.path.exists(os.path.join(WAZUH_PATH, 'queue', 'db', 'wdb')):
                os.remove(os.path.join(WAZUH_PATH, 'queue', 'db', 'wdb'))
            if os.path.exists(os.path.join(WAZUH_PATH, 'queue', 'cluster', 'c-internal.sock')):
                os.remove(os.path.join(WAZUH_PATH, 'queue', 'cluster', 'c-internal.sock'))
        else:
            for item in path:
                os.remove(item)
    except FileNotFoundError:
        pass


def control_service(action, daemon=None, debug_mode=False):
    """Perform the stop, start and restart operation with Wazuh.

    It takes care of the current OS to interact with the service and the type of installation (agent or manager).

    Args:
        action ({'stop', 'start', 'restart'}): Action to be done with the service/daemon.
        daemon (str, optional): Name of the daemon to be controlled. None to control the whole Wazuh service. Default `None`
        debug_mode (bool, optional) : Run the specified daemon in debug mode. Default `False`
    Raises:
        ValueError: If `action` is not contained in {'start', 'stop', 'restart'}.
        ValueError: If the result is not equal to 0.
    """
    valid_actions = ('start', 'stop', 'restart')
    if action not in valid_actions:
        raise ValueError(f'action {action} is not one of {valid_actions}')

    if sys.platform == 'win32':
        if action == 'restart':
            control_service('stop')
            control_service('start')
            result = 0
        else:
            command = subprocess.run(["net", action, "WazuhSvc"], stderr=subprocess.PIPE)
            result = command.returncode
            if command.returncode != 0:
                if action == 'stop' and 'The Wazuh service is not started.' in command.stderr.decode():
                    result = 0
                print(command.stderr.decode())
    else:  # Default Unix
        if daemon is None:
            if sys.platform == 'darwin' or sys.platform == 'sunos5':
                result = subprocess.run([f'{WAZUH_PATH}/bin/wazuh-control', action]).returncode
            else:
                result = subprocess.run(['service', get_service(), action]).returncode
            action == 'stop' and delete_sockets()
        else:
            if action == 'restart':
                control_service('stop', daemon=daemon)
                control_service('start', daemon=daemon)
            elif action == 'stop':
                processes = []

                for proc in psutil.process_iter():
                    if daemon in proc.name():
                        try:
                            processes.append(proc)
                        except psutil.NoSuchProcess:
                            pass
                try:
                    for proc in processes:
                        proc.terminate()

                    _, alive = psutil.wait_procs(processes, timeout=5)

                    for proc in alive:
                        proc.kill()
                except psutil.NoSuchProcess:
                    pass

                delete_sockets(WAZUH_SOCKETS[daemon])
            else:
                daemon_path = os.path.join(WAZUH_PATH, 'bin')
                check_call([f'{daemon_path}/{daemon}', '' if not debug_mode else '-dd'])
            result = 0

    if result != 0:
        raise ValueError(f"Error when executing {action} in daemon {daemon}. Exit status: {result}")


def get_process(search_name):
    """
    Search process by its name.

    Args:
        search_name (str): Name of the process to be fetched.

    Returns:
        `psutil.Process` or None: First occurrence of the process object matching the `search_name` or None if no process has been found.
    """
    for proc in psutil.process_iter(attrs=['name']):
        if proc.name() == search_name:
            return proc

    return None


def get_process_cmd(search_cmd):
    """
    Search process by its command line.

    Args:
        search_cmd (str): Name of the command to be fetched.

    Returns:
        `psutil.Process` or None: First occurrence of the process object matching the `search_cmd` or None if no process has been found.
    """
    for proc in psutil.process_iter(attrs=['pid', 'name', 'cmdline']):
        command = next((command for command in proc.cmdline() if search_cmd in command), None)
        if command:
            return proc


def check_daemon_status(daemon=None, running=True, timeout=10, extra_sockets=None):
    """Check Wazuh daemon status.

    Args:
        daemon (str, optional):  Wazuh daemon to check. Default `None`
        running (bool, optional): True if the daemon is expected to be running False if it is expected to be stopped. Default `True`
        timeout (int, optional): Timeout value for the check. Default `10`
        extra_sockets (list, optional): Additional sockets to check. They may not be present in default configuration

    Raises:
        TimeoutError: If the daemon status is wrong after timeout seconds.
    """
    if extra_sockets is None:
        extra_sockets = []
    for _ in range(3):
        # Check specified daemon/s status
        daemon_status = subprocess.run(['service', get_service(), 'status'], stdout=subprocess.PIPE).stdout.decode()
        if f"{daemon if daemon is not None else ''} {'not' if running else 'is'} running" not in daemon_status:
            # Construct set of socket paths to check
            if daemon is None:
                socket_set = {path for array in WAZUH_SOCKETS.values() for path in array}
            else:
                socket_set = {path for path in WAZUH_SOCKETS[daemon]}
            # We remove optional sockets and add extra sockets to the set to check
            socket_set.difference_update(WAZUH_OPTIONAL_SOCKETS)
            socket_set.update(extra_sockets)
            # Check specified socket/s status
            for socket in socket_set:
                if os.path.exists(socket) is not running:
                    break
            else:
                # Finish main for loop if both daemon and socket checks are ok
                break

        time.sleep(timeout/3)
    else:
        raise TimeoutError(f"{'wazuh-service' if daemon is None else daemon} "
                           f"{'is not' if running else 'is'} running")


def delete_dbs():
    """Delete all wazuh-db databases"""
    for root, dirs, files in os.walk(QUEUE_DB_PATH):
        for file in files:
            os.remove(os.path.join(root, file))


def check_if_process_is_running(process_name):
    """
    Check if process is running

    Args:
        process_name (str): Name of process

    Returns
        boolean: True if process is running, False otherwise
    """
    is_running = False
    try:
        is_running = process_name in (p.name() for p in psutil.process_iter())
    except psutil.NoSuchProcess:
        pass

    return is_running
