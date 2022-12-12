# Wazuh agent dockerizer
# Copyright (C) 2015-2022, Wazuh Inc.
# January 28, 2020.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# Python 3.8 or greater.
# Dependencies: pip3 install docker-compose

# Standard library imports.
import logging
import random
import string

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Union, List

# Third party imports.
import docker

# Wazuh Testing framework imports.
from wazuh_testing.qa_ctl import QACTL_LOGGER
from wazuh_testing.qa_ctl.deployment.docker_wrapper import DockerWrapper
from wazuh_testing.tools.exceptions import QAValueError
from wazuh_testing.tools.file import write_file, read_file


LOGGER = logging.getLogger(QACTL_LOGGER)


class AgentsDockerizer:
    '''Class to handle multiple agents running on containers at the same time.
    It uses a thread pool to executes commands in several DockerWrapper instances
    at once.

    Args:
        agent_conf (str): An ossec.conf to apply to all agents.
        quantity (int, Optional): Amount of agents to build, default 10.
        package_uri (str, Optional): Agent package URL, default agent 4.4.0.

    Attributes:
        agents (list[DockerWrapper]): List that contains all the agents built.
        dockerfile_path (str): Path to the Dockerfile.
        quantity (int): Amount of agents.
    '''

    agents: List[DockerWrapper] = []
    dockerfile_path = Path(Path(__file__).parent, 'dockerfiles', 'agents')
    __wazuh_control = '/var/ossec/bin/wazuh-control'

    def __init__(self, agent_conf: str, quantity: int = 10, package_uri: str = None) -> None:
        self.quantity = quantity
        write_file(Path(self.dockerfile_path, 'ossec.conf'), agent_conf)
        self.set_agent_package_uri(package_uri)
        self.build_agents()

    def build_agents(self):
        '''Builds and starts the wazuh-agents in docker containers.

        Function that initializes multiple DockerWrapper instances to
        handle all the defined agents. If the agents are already built
        it returns doing nothing.

        Args:
            None

        Returns:
            None
        '''
        if self.agents:
            LOGGER.warning('Agents already built.')
            return

        client = docker.from_env()

        def build():
            name = self.__generate_name()
            container = DockerWrapper(client, str(self.dockerfile_path), name)
            self.agents.append(container)
            LOGGER.info(f'Container built: {name}')
            container.run()

        with ThreadPoolExecutor(self.quantity) as executor:
            futures = [executor.submit(build) for _ in range(self.quantity)]
        [future.result() for future in futures]

    def set_agent_package_uri(self,  package_uri: str = '') -> None:
        '''Set the desired wazuh-agent package to be built.

        Function that reads a Dockerfile template used to set the agent package
        URL, then writes a Dockerfile that will be used to build the agents.
        It allows to build wazuh-agents from any version, by default it uses
        a 4.4.0 wazuh-agent package.

        Args:
            package_uri (str, Optional): Desired wazuh-agent package URL.

        Returns:
            None
        '''
        if not package_uri:
            package_uri = 'https://packages-dev.wazuh.com/pre-release/' + \
                          'apt/pool/main/w/wazuh-agent/wazuh-agent_4.4.0-1_amd64.deb'

        template = read_file(Path(self.dockerfile_path, 'template'))
        dockerfile = template.replace('|AGENT_URL|', package_uri)

        write_file(Path(self.dockerfile_path, 'Dockerfile'), dockerfile)

    def start(self):
        '''Start wazuh-agent services.
        Args:
            None

        Returns:
            str, List[str]: Output of the command.
        '''
        command = f'{self.__wazuh_control} start'
        LOGGER.info('Starting all the agents')
        return self.execute(command)

    def status(self):
        '''Check wazuh-agent services status.
        Args:
            None

        Returns:
            str, List[str]: Output of the command.
        '''
        command = f'{self.__wazuh_control} status'
        LOGGER.info('Checking agents status')
        return self.execute(command)

    def execute(self, command: Union[str, List[str]]):
        '''Execute a command in the agents hosts.
        Args:
            command (str, List[str]): Command to execute in containers.

        Returns:
            str, List[str]: Output of the command.
        '''
        LOGGER.info(f'Executing the command {command} in all agents')
        return self.__broadcast_to_docker('execute', f'bash -c "{command}"')

    def stop(self):
        '''Stop wazuh-agent services.
        Args:
            None

        Returns:
            str, List[str]: Output of the command.
        '''
        command = f'{self.__wazuh_control} stop'
        LOGGER.info('Stoping all the agents')
        return self.execute(command)

    def destroy(self):
        '''Destroys all the agent containers.
        Args:
            None

        Returns:
            None
        '''
        LOGGER.info('Destroying all the agents')
        self.__broadcast_to_docker('destroy')
        self.agents.clear()

    def __generate_name(self):
        '''Retrieves a random generated name for the containers.

        Args:
            None

        Returns:
            None
        '''
        return ''.join((random.choice(string.ascii_uppercase)
                        for _ in range(10)))

    def __broadcast_to_docker(self, func: str, *args: tuple, **kwargs: dict):
        '''Executes a command with its args (if included) on every container
        instance at once.

        Function that executes the received function on every DockerWrapper
        instance at the same time using ThreadPoolExecutor

        Args:
            func (Action): The DockerWrapper function to execute.
            *args (tuple): Optional positional arguments for the function execution.
            **kwargs (dict): Optional named arguments for the function execution.

        Returns:
            list[Any]: Output of the function executed on each DockerWrapper instance.
        '''
        if not self.agents:
            raise QAValueError('No agents built', LOGGER.error, QACTL_LOGGER)

        with ThreadPoolExecutor(self.quantity) as executor:
            futures = [executor.submit(getattr(a, func), *args, **kwargs)
                       for a in self.agents]

        return [future.result() for future in futures]
