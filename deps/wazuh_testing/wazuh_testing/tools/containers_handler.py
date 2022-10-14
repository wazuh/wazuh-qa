# Copyright (C) 2015-2022, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

# Standard library imports
import random
import string
from enum import Enum
from concurrent.futures import ThreadPoolExecutor
from types import FunctionType

# Third party imports
import docker
from docker import DockerClient

# Testing Framework imports
from wazuh_testing.qa_ctl.deployment.docker_wrapper import DockerWrapper


class Action(str, Enum):
    '''An Enum class to store all actions applicable to containers.

    The current Actions the Container Handler supports are these:

        START: Action to start the containers.
        RESTART: Action to restart the containers.
        STATUS: Action that returns the status of the containers.
        EXECUTE: Action to execute a command in the containers.
        STOP: Action to pause or stop the containers.
        REMOVE: Action to delete the containers.

    Example use case, build and start the containers:

        handler = ContainerHandler('/path/to/image')
        handler.broadcast_to_containers(Action.START)
    '''
    START = 'start'
    RESTART = 'restart'
    STATUS = 'status'
    EXECUTE = 'execute'
    STOP = 'halt'
    REMOVE = 'destroy'

    @classmethod
    def has_value(cls, value: str) -> bool:
        '''Method to validate if a value is an usable Action.

        Args:
            value (str): The value that will be checked.

        Returns:
            bool: True if the value is usable as Action, else false.
        '''
        return value in cls._value2member_map_


class ContainerHandler:
    '''Class that handles multiple containers connections at the same time.
    Using a thread pool executes commands in several DockerWrapper instances
    at the same time.

    Args:
        dockerfile_path (str): Path to the Dockerfile.
        client (DockerClient, optional): Client instance to connect to docker server.
        quantity (int, optional): Amount of containers to handle. Default: 5.
        names_len (int, optional): Lenght of the containers names. Default: 5.

    Attributes:
        dockerfile_path (str): Path to the Dockerfile.
        client (DockerClient): Client instance to connect to docker server.
        quantity (int): Amount of containers to handle.
        names_len (int): Lenght of the containers names.
        actions (Action): Enum with the available actions to perform in the containers.
        containers (list[DockerWrapper]): List that contains all the running containers.
    '''

    actions = Action
    containers: list[DockerWrapper] = []

    def __init__(self, dockerfile_path: str, client: DockerClient = None, quantity: int = 5, names_len: int = 5) -> None:
        self.dockerfile_path = dockerfile_path
        self.client = client if client else docker.from_env()
        self.quantity = quantity
        self.names_len = names_len

        self.__thread_pool(self.__build)

    def broadcast_to_containers(self, action: Action, command: str | list[str] = None) -> list[dict]:
        '''Executes an action and a command (if its included) with it on every
        container, the action must an Action Enum value. The command is commonly
        used only with the Action EXECUTE.

        Args:
            action (Action): The action to perform on the containers.
            command (str): The command to be executed with the action. 

        Returns:
            list[dict]: Output of the execution in each container.
        '''
        if not Action.has_value(action):
            print(f'Invalid action "{action}"!')
            return
        arguments = (action, command) if command else (action,)
        containers_output = self.__thread_pool(*arguments)

        self.containers.clear() if action == Action.REMOVE else None
        return containers_output

    def __thread_pool(self, func: FunctionType | Action, *args: tuple, **kwargs: dict) -> list[dict | None]:
        '''Runs the received function or action in multiple threads, if the function
        is an action it will generate the corresponding function.
        The amount of threads is defined by self.quantity or the amount of containers.

        Args: 
            func (function | Action): Function or action to be executed in multiple threads.
            *args (tuple): Optional positional arguments added to the function execution.
            **kwargs (dict): Optional named arguments added to the function execution.

        Returns:
            list[dict | None]: List of dict with the results of the execution in the containers.
        '''
        output = []
        with ThreadPoolExecutor(self.quantity) as executor:
            if Action.has_value(func):
                for cont in self.containers:
                    future = executor.submit(getattr(cont, func),
                                             *args, **kwargs)
                    output.append({'container': cont.name, 'result': future})
            else:
                [executor.submit(func, *args, **kwargs)
                 for _ in range(self.quantity)]

        [i.update({'result': i['result'].result()}) for i in output]
        return output

    def __build(self) -> None:
        '''Builds and runs a container and adds it to the containers list.

        Args:
            None

        Returns: 
            None  
        '''
        name = self._generate_container_name()
        container = DockerWrapper(self.client, self.dockerfile_path, name)
        container.run()
        self.containers.append(container)
        print(f'Builded container: {name}')

    def _generate_container_name(self) -> str:
        '''Generates containers names with random uppercase chars, the length
        of the name is defined by the names_len instance variable.

        Args:
            None

        Returns:
            str: A random generated uppercase string.
        '''
        return ''.join((random.choice(string.ascii_uppercase)
                        for _ in range(self.names_len)))
