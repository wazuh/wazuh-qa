import pytest
import re
from pathlib import Path

from wazuh_testing.tools.file import remove_file, copy, write_file, read_file
from wazuh_testing.tools.utils import get_current_ip
from wazuh_testing.tools.virtualization import AgentDockerizer


AGENT_CONFIG_PATH = Path(Path(Path(__file__).parent, 'data', 'ossec.conf'))


@pytest.fixture
def dockerized_agents(agents_config: str, metadata: dict) -> AgentDockerizer:
    agents = AgentDockerizer(agents_config, metadata.get('agents_amount'))
    yield agents
    agents.destroy()


@pytest.fixture
def agents_config():
    '''Set wazuh configuration

    Args:
        configuration (dict): Configuration template data to write in the ossec.conf
    '''

    def set_current_ip_to_agent_config(config: str) -> str:
        reg = '(?<=%s).*?(?=%s)' % ('<address>', '</address>')
        r = re.compile(reg, re.DOTALL)
        return r.sub(get_current_ip(), config)

    # Save current configuration
    backup_config = read_file(AGENT_CONFIG_PATH)
    # Set the agents configuration for this execution
    test_config = set_current_ip_to_agent_config(backup_config)
    write_file(AGENT_CONFIG_PATH, test_config)

    yield test_config
    # Restore previous configuration
    write_file(AGENT_CONFIG_PATH, backup_config)
