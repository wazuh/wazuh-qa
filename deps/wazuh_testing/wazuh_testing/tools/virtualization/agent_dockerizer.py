import random
import string
import docker

from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from docker_wrapper import DockerWrapper


class AgentDockerizer:

    agents: DockerWrapper = []

    def __init__(self, ossec_conf=None, dockerfile=None, client=None, quantity=10) -> None:
        self.quantity = quantity
        
        if not dockerfile:
            self.image_path = f"{Path(__file__)}/Dockerfile"
        else:
            self.image_path = dockerfile
        
        self.client = client if client else docker.from_env()

        self._build_agents()

    def start(self):
        if not self.agents:
            print("There are not agents builded")
            return
        print("Starting all the agents")
        self._broadcast_to_agents("run")

    def execute(self, command: str | list[str]):
        if not self.agents:
            print("There are not agents builded")
            return
        print(f"Executing the command {command} in all agents")
        self._broadcast_to_agents("execute", command)

    def stop(self):
        if not self.agents:
            print("There are not agents builded")
            return
        print("Stoping all the agents")
        self._broadcast_to_agents("halt")

    def remove(self):
        if not self.agents:
            print("There are not agents builded")
            return
        print("Removing all the agents")
        self._broadcast_to_agents("destroy")

    def _generate_name(self, name='', chars=5):
        return name.join((random.choice(string.ascii_uppercase) for _ in range(chars)))

    def _build_agents(self):
        def build():
            name = self._generate_name()
            container = DockerWrapper(self.client, self.image_path, name)
            self.agents.append(container)
            print(f'Builded container: {name}')

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
