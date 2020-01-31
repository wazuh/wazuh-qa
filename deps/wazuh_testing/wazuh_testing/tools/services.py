# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import subprocess
import sys
import time
from subprocess import check_call

import psutil

from wazuh_testing.tools import WAZUH_PATH, WAZUH_SERVICE
from wazuh_testing.tools.configuration import write_wazuh_conf


def restart_wazuh_daemon(daemon):
    """
    Restarts a Wazuh daemon.

    Use this function to avoid restarting the whole service and all of its daemons.

    Parameters
    ----------
    daemon : str
        Name of the executable file of the daemon in /var/ossec/bin
    """
    for proc in psutil.process_iter(attrs=['name']):
        if proc.name() == daemon:
            proc.kill()

    daemon_path = os.path.join(WAZUH_PATH, 'bin')
    check_call([f'{daemon_path}/{daemon}'])


def restart_wazuh_with_new_conf(new_conf, daemon='ossec-syscheckd'):
    """
    Restart Wazuh service applying a new ossec.conf

    Parameters
    ----------
    new_conf : ET.ElementTree
        New config file.
    daemon : str, optional
        Daemon to restart when applying the configuration.
    """
    write_wazuh_conf(new_conf)
    control_service('restart', daemon=daemon)


def control_service(action, daemon=None, debug_mode=False):
    """Perform the stop, start and restart operation with Wazuh.

    It takes care of the current OS to interact with the service and the type of installation (agent or manager).

    Parameters
    ----------
    action : {'stop', 'start', 'restart'}
        Action to be done with the service/daemon.
    daemon : str, optional
        Name of the daemon to be controlled. None to control the whole Wazuh service. Default `None`
    debug_mode : bool, optional
        Run the specified daemon in debug mode. Default `False`

    Raises
    ------
    ValueError
        If `action` is not contained in {'start', 'stop', 'restart'}.
    ValueError
        If the result is not equal to 0.
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
            result = 0 if subprocess.run(["net", action, "OssecSvc"]).returncode in (0, 2) else \
                subprocess.run(["net", action, "OssecSvc"]).returncode
    else:  # Default Unix
        if daemon is None:
            if sys.platform == 'darwin' or sys.platform == 'sunos5':
                result = subprocess.run([f'{WAZUH_PATH}/bin/ossec-control', action]).returncode
            else:
                result = subprocess.run(['service', WAZUH_SERVICE, action]).returncode
        else:
            if action == 'restart':
                control_service('stop', daemon=daemon)
                control_service('start', daemon=daemon)
            elif action == 'stop':
                for proc in psutil.process_iter(attrs=['name']):
                    proc.name() == daemon and proc.kill()
            else:
                daemon_path = os.path.join(WAZUH_PATH, 'bin')
                check_call([f'{daemon_path}/{daemon}', '' if not debug_mode else '-d'])
            result = 0

    if result != 0:
        raise ValueError(f"Error when executing {action} in daemon {daemon}. Exit status: {result}")


def get_process(search_name):
    """
    Search process by its name.

    Parameters
    ----------
    search_name : str
        Name of the process to be fetched.

    Returns
    -------
    `psutil.Process` or None
        First occurrence of the process object matching the `search_name` or None if no process has been found.
    """
    for proc in psutil.process_iter(attrs=['name']):
        if proc.name() == search_name:
            return proc

    return None


def check_daemon_status(daemon=None, running=True, timeout=10):
    """Check Wazuh daemon status.

    Parameters
    ----------
    daemon : str, optional
        Wazuh daemon to check. Default `None`
    running : bool, optional
        True if the daemon is expected to be running False if it is expected to be stopped. Default `True`
    timeout : int, optional
        Timeout value for the check. Default `10`

    Raises
    ------
    TimeoutError
        If the daemon status is wrong after timeout seconds.
    """
    for _ in range(3):
        daemon_status = subprocess.run(['service', 'wazuh-manager', 'status'],
                                       stdout=subprocess.PIPE).stdout.decode()
        if f"{daemon if daemon is not None else ''} {'not' if running is True else 'is'} running" not in daemon_status:
            break
        time.sleep(timeout/3)
    else:
        raise TimeoutError(f"{'wazuh-service' if daemon is None else daemon} "
                           f"{'is not' if running is True else 'is'} running")


def delete_sockets(path=None):
    """Delete a Wazuh socket file or all of them if None is specified.

    Parameters
    ----------
    path : str, optional
        Socket path relative to WAZUH_PATH. Default `None`
    """
    try:
        if path is None:
            path = os.path.join(WAZUH_PATH, 'queue', 'ossec')
            for file in os.listdir(path):
                os.remove(os.path.join(path, file))
            os.remove(os.path.join(WAZUH_PATH, 'queue', 'db', 'wdb'))
        else:
            os.remove(os.path.join(WAZUH_PATH, path))
    except FileNotFoundError:
        pass
