import random
import string
import logging

from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

import docker

from docker_wrapper import DockerWrapper


logger = logging.getLogger("AgentDockerizer")


class AgentDockerizer:

    agents: DockerWrapper = []
    wazuh_control = "/var/ossec/bin/wazuh-control"

    def __init__(self, manager_ip: str, ossec_conf: str = None,  
                 dockerfile: str = None, quantity: int = 10) -> None:
        self.manager_ip = manager_ip
        self.quantity = quantity

        if not dockerfile:
            self.image_path = f"{Path(__file__)}/Dockerfile"
        else:
            self.image_path = dockerfile

        self._build_agents()

    def start(self):
        if not self.agents:
            logger.error("There are not agents builded")
            return
        logger.info("Starting all the agents")
        return self._broadcast_to_agents("execute", f"{self.wazuh_control} start")

    def execute(self, command: str | list[str]):
        if not self.agents:
            logger.error("There are not agents builded")
            return
        logger.info(f"Executing the command {command} in all agents")
        return self._broadcast_to_agents("execute", command)

    def stop(self):
        if not self.agents:
            logger.error("There are not agents builded")
            return
        logger.info("Stoping all the agents")
        return self._broadcast_to_agents("execute", f"{self.wazuh_control} stop")

    def destroy(self):
        if not self.agents:
            logger.error("There are not agents builded")
            return
        self._broadcast_to_agents("halt")
        logger.info("Removing all the agents")
        self._broadcast_to_agents("destroy")

    def _generate_name(self, name: str = '', chars: int = 5):
        return name.join((random.choice(string.ascii_uppercase)
                          for _ in range(chars)))

    def _build_agents(self):
        client = docker.from_env()

        def build():
            name = self._generate_name()
            container = DockerWrapper(client, self.image_path, name)
            self.agents.append(container)
            logger.info(f'Builded container: {name}')
            container.run()

        with ThreadPoolExecutor(self.quantity) as executor:
            [executor.submit(build) for _ in range(self.quantity)]

    def _broadcast_to_agents(self, func, *args, **kwargs):
        with ThreadPoolExecutor(self.quantity) as executor:
            futures = [executor.submit(getattr(a, func), *args, **kwargs)
                       for a in self.agents]

        return [future.result() for future in futures]


if __name__ == '__main__':
    handler = AgentDockerizer('./wazuh-agent-docker', quantity=5)
    # Executing actions on all the agents
    handler.start()
    handler.execute("/var/ossec/bin/wazuh-control stop")
    handler.execute("/var/ossec/bin/wazuh-control start")
    handler.stop()
    handler.remove()
