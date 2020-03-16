# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import queue
import time
from multiprocessing import Process, Queue

import testinfra
import yaml

from wazuh_testing import logger
from wazuh_testing.tools import WAZUH_CONF
from wazuh_testing.tools.monitoring import Timer


def threaded(fn):
    """Wrapper for enable multiprocessing inside a class

    Parameters
    ----------
    fn : callable
        Function to be executed in a new thread

    Returns
    -------
    wrapper
    """

    def wrapper(*args, **kwargs):
        thread = Process(target=fn, args=args, kwargs=kwargs)
        thread.start()
        return thread

    return wrapper


class HostManager:

    def __init__(self, inventory_path: str):
        """Constructor of host manager class.

        Parameters
        ----------
        inventory_path : str
            Ansible inventory path
        """
        self.inventory_path = inventory_path

    def get_host(self, host: str):
        """Get the Ansible object for communicating with the specified host.

        Parameters
        ----------
        host : str
            Hostname

        Returns
        -------
        testinfra.modules.base.Ansible
            Host instance from hostspec
        """
        return testinfra.get_host(f"ansible://{host}?ansible_inventory={self.inventory_path}").ansible

    def move_file(self, host: str, src_path: str, dest_path: str, check: bool = False):
        """Move from src_path to the desired location dest_path for the specified host.

        Parameters
        ----------
        host : str
            Hostname
        src_path : str
            Source path
        dest_path :
            Destination path
        check : bool
            Ansible check mode("Dry Run")(https://docs.ansible.com/ansible/latest/user_guide/playbooks_checkmode.html),
            by default it is enabled so no changes will be applied
        """
        self.get_host(host)("copy", f"src={src_path} dest={dest_path} owner=ossec group=ossec mode=0775", check=check)

    def add_block_to_file(self, host: str, path: str, replace: str, before: str, after, check: bool = False):
        """Add text block to desired file.

        Parameters
        ----------
        host : str
            Hostname
        path : str
            Path of the file
        replace : str
            Text to be inserted in the file
        before : str
            Lower stop of the block to be replaced
        after : str
            Upper stop of the block to be replaced
        check : bool
            Ansible check mode("Dry Run")(https://docs.ansible.com/ansible/latest/user_guide/playbooks_checkmode.html),
            by default it is enabled so no changes will be applied
        """
        replace = f'{after}{replace}{before}'
        self.get_host(host)("replace", f"path={path} regexp='{after}[\s\S]+{before}' replace='{replace}'", check=check)

    def control_service(self, host: str, service: str = 'wazuh', state: str = "started", check: bool = False):
        """Control the specified service.

        Parameters
        ----------
        host : str
            Hostname
        service : str
            Service to be controlled
        state : str
            Final state in which service must end
        check : bool
            Ansible check mode("Dry Run")(https://docs.ansible.com/ansible/latest/user_guide/playbooks_checkmode.html),
            by default it is enabled so no changes will be applied
        """
        if service == 'wazuh':
            service = 'wazuh-agent' if 'agent' in host else 'wazuh-manager'
        self.get_host(host)("service", f"name={service} state={state}", check=check)

    def clear_file(self, host: str, file_path: str, check: bool = False):
        """Truncate the specified file.

        Parameters
        ----------
        host : str
            Hostname
        file_path : str
            File path to be truncated
        check : bool
            Ansible check mode("Dry Run")(https://docs.ansible.com/ansible/latest/user_guide/playbooks_checkmode.html),
            by default it is enabled so no changes will be applied
        """
        self.get_host(host)("copy", f"dest={file_path} content='' force=yes", check=check)

    def get_file_content(self, host: str, file_path: str, regex: str = '.', check: bool = False):
        """Get the content of the specified file.

        Parameters
        ----------
        host : str
            Hostname
        file_path : str
            Path of the file
        regex : str
            Regex applied to the content of the file (Linux like)
        check : bool
            Ansible check mode("Dry Run")(https://docs.ansible.com/ansible/latest/user_guide/playbooks_checkmode.html),
            by default it is enabled so no changes will be applied
        """
        return self.get_host(host)("shell", f"cat {file_path} | grep '{regex}'", check=check)['stdout']

    def apply_config(self, config_yml_path: str, dest_path: str = WAZUH_CONF, clear_files: list = None,
                     restart_services: list = None):
        """Apply the configuration describe in the config_yml_path to the environment.

        Parameters
        ----------
        config_yml_path : str
            Path to the yml file that contains the configuration to be applied
        dest_path : str
            Destination file
        clear_files : list
            List of files to be truncated
        restart_services : list
            List of services to be restarted
        """
        with open(config_yml_path, mode='r') as config_yml:
            config = yaml.safe_load(config_yml)
        for host, payload in config.items():
            for block in payload:
                self.add_block_to_file(host=host, path=dest_path, after=block['after'],
                                       before=block['before'], replace=block['content'])

            if restart_services:
                for service in restart_services:
                    self.control_service(host=host, service=service, state='restarted')
            if clear_files:
                for log in clear_files:
                    self.clear_file(host=host, file_path=log)


class HostMonitor:

    def __init__(self, inventory_path, file_path, time_step=0.5):
        self.host_manager = HostManager(inventory_path=inventory_path)
        self.file_path = file_path
        self.time_step = time_step
        self.pool = Queue()
        self._continue = False
        self._abort = False
        self.timeout_timer = None
        self.extra_timer = None
        self.extra_timer_is_running = False
        self.handlers = list()

    def _monitor(self, host, regex, timeout_extra=0):
        """Wait for regex to be founded in the file.

        Parameters
        ----------
        host : str
            Hostname
        regex : str
            Regex applied to the content of the file (Linux like)
        timeout_extra : int or float
            Extra time in addition to the timeout
        """
        self.extra_timer_is_running = False
        while self._continue:
            if self._abort and not self.extra_timer_is_running:
                self.stop()
                self.pool.put({host: TimeoutError()})
            result = self.host_manager.get_file_content(host, self.file_path, regex)
            if result == '':
                time.sleep(self.time_step)
            else:
                self.pool.put({host: result})
                if timeout_extra > 0 and not self.extra_timer_is_running:
                    self.extra_timer = Timer(timeout_extra, self.stop)
                    self.extra_timer.start()
                    self.extra_timer_is_running = True
                elif timeout_extra == 0:
                    self.stop()

    def run(self, messages_path):
        """This method creates and destroy the needed processes for the messages founded in messages_path.

        Parameters
        ----------
        messages_path : str
            Path to the messages file
        """
        with open(messages_path, mode='r') as config_yml:
            expected_messages = yaml.safe_load(config_yml)
        for host, payload in expected_messages.items():
            for case in payload:
                logger.debug(f'Starting HostMonitor for \'{host}\' and this callback \'{case["regex"]}\'')
                self.handlers.append(self._start(host=host, regex=case['regex'], timeout=case['timeout']))

        self.check_messages()
        self.close_processes()

    @threaded
    def _start(self, host, regex='.*', timeout=-1, timeout_extra=0):
        """Start the host monitoring until the stop method is called.

        Parameters
        ----------
        host : str
            Hostname
        regex : str
            Regex applied to the content of the file (Linux like)
        timeout : int or float
            Maximum waiting time to receive the message
        timeout_extra : int of float
            Extra time in addition to the timeout

        Returns
        -------
        instance
        """
        if not self._continue:
            self._continue = True
            self._abort = False
            if timeout > 0:
                self.timeout_timer = Timer(timeout, self.abort)
                self.timeout_timer.start()
            self._monitor(host, regex=regex, timeout_extra=timeout_extra)
        return self

    def stop(self):
        """Stop the file monitoring. It can be restart calling the start method."""
        self._continue = False
        if self.timeout_timer:
            self.timeout_timer.cancel()
            self.timeout_timer.join()
        if self.extra_timer and self.extra_timer_is_running:
            self.extra_timer.cancel()
            self.extra_timer_is_running = False
        return self

    def abort(self):
        """Abort because of timeout."""
        self._abort = True
        return self

    def check_messages(self):
        """Check received messages."""
        received = 0
        while received < len(self.handlers):
            try:
                message = self.pool.get(block=False)
                received += 1
                logger.debug(f'Received message: \'{message}\'')
                assert not isinstance(message[list(message.keys())[0]], TimeoutError) and not isinstance(message,
                                                                                                         Exception)
            except queue.Empty:
                time.sleep(0.1)

    def close_processes(self):
        """Close all opened processes."""
        for handler in self.handlers:
            handler.join()
