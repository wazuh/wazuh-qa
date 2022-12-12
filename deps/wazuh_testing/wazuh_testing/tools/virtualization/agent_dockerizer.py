import random
import string
import logging

from pathlib import Path
from typing import Union, List
from concurrent.futures import ThreadPoolExecutor

import docker

from .docker_wrapper import DockerWrapper
from wazuh_testing.qa_ctl import QACTL_LOGGER
from wazuh_testing.tools.exceptions import QAValueError
from wazuh_testing.tools.file import write_file, read_file


LOGGER = logging.getLogger(QACTL_LOGGER)


class AgentDockerizer:

    agents: List[DockerWrapper] = []
    dockerfile_path = Path(Path(__file__).parent, 'dockerfiles', 'agents')
    wazuh_control = '/var/ossec/bin/wazuh-control'

    def __init__(self, agent_conf: str, quantity: int = 10,
                 package_uri: str = None) -> None:
        self.quantity = quantity
        write_file(Path(self.dockerfile_path, 'ossec.conf'), agent_conf)
        self._set_agent_package_url(package_uri)
        self._build_agents()

    def start(self):
        self.validate_agents_are_built()
        command = f'{self.wazuh_control} start'
        LOGGER.info('Starting all the agents')
        return self.execute(command)

    def status(self):
        self.validate_agents_are_built()
        command = f'{self.wazuh_control} status'
        LOGGER.info('Checking agents status')
        return self.execute(command)

    def execute(self, command: Union[str, List[str]]):
        self.validate_agents_are_built()
        LOGGER.info(f'Executing the command {command} in all agents')
        return self._broadcast_to_agents('execute', f'bash -c "{command}"')

    def stop(self):
        self.validate_agents_are_built()
        command = f'{self.wazuh_control} stop'
        LOGGER.info('Stoping all the agents')
        return self.execute(command)

    def destroy(self):
        self.stop()
        LOGGER.info('Destroying all the agents')
        self._broadcast_to_agents('destroy')
        self.agents.clear()

    def validate_agents_are_built(self):
        if not self.agents:
            raise QAValueError('No agents built', LOGGER.error, QACTL_LOGGER)
        return True

    def _set_agent_package_url(self,  package_url: str = '') -> None:
        if not package_url:
            package_url = 'https://packages-dev.wazuh.com/pre-release/' + \
                          'apt/pool/main/w/wazuh-agent/wazuh-agent_4.4.0-1_amd64.deb'
        # Read template and write the expected Dockerfile
        template = read_file(Path(self.dockerfile_path, 'template'))
        dockerfile = template.replace('|AGENT_URL|', package_url)
        write_file(Path(self.dockerfile_path, 'Dockerfile'), dockerfile)

    def _generate_name(self, name: str = '', chars: int = 5):
        return name.join((random.choice(string.ascii_uppercase)
                          for _ in range(chars)))

    def _build_agents(self):
        client = docker.from_env()

        def build():
            name = self._generate_name()
            container = DockerWrapper(client, str(self.dockerfile_path), name)
            self.agents.append(container)
            LOGGER.info(f'Container built: {name}')
            container.run()

        with ThreadPoolExecutor(self.quantity) as executor:
            futures = [executor.submit(build) for _ in range(self.quantity)]
        [future.result() for future in futures]

    def _broadcast_to_agents(self, func, *args, **kwargs):
        with ThreadPoolExecutor(self.quantity) as executor:
            futures = [executor.submit(getattr(a, func), *args, **kwargs)
                       for a in self.agents]

        return [future.result() for future in futures]


if __name__ == '__main__':
    handler = AgentDockerizer('./wazuh-agent-docker', quantity=5)
    # Executing actions on all the agents docker exec -it CONTAINER_ID bash -c 'mysql_tzinfo_to_sql /usr/share/zoneinfo | mysql mysql'
    handler.start()
    handler.execute('/var/ossec/bin/wazuh-control stop')
    handler.execute('/var/ossec/bin/wazuh-control start')
    handler.stop()
    handler.remove()
