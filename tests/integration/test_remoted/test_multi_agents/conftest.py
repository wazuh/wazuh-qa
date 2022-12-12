# Standard library imports.
import pytest
import re
from pathlib import Path

# Wazuh Testing framework imports.
from wazuh_testing.tools.configuration import set_section_wazuh_conf
from wazuh_testing.tools.file import read_file
from wazuh_testing.tools.utils import get_current_ip
from wazuh_testing.tools.virtualization import AgentsDockerizer


AGENT_CONFIG_PATH = Path(Path(Path(__file__).parent, 'data', 'conf_template'))


@pytest.fixture(scope='function')
def dockerized_agents(agents_config: str, metadata: dict) -> AgentsDockerizer:
    '''Build and cleanup dockerized agents

    Args:
        agents_config (str): Agents ossec.conf.
        metadata (dict): Test metadata to get the agents_amount from.
    Yield:
        AgentsDockerizer: Instance to handle the dockerized agents.
    '''
    agents = AgentsDockerizer(agents_config, metadata.get('agents_amount'))

    yield agents

    agents.stop()
    agents.destroy()


@pytest.fixture(scope='function')
def agents_config(configuration: dict) -> str:
    '''Set wazuh configuration

    Args:
        configuration (dict): Configuration data to set in the ossec.conf.
    Yield:
        str: An ossec.conf for the dockerized agents.
    '''

    def set_current_ip_to_agent_config(config: str) -> str:
        reg = '(?<=%s).*?(?=%s)' % ('<address>', '</address>')
        r = re.compile(reg, re.DOTALL)
        return r.sub(get_current_ip(), config)

    # Get template and configuration sections
    template = read_file(AGENT_CONFIG_PATH)
    config_sections = configuration.get('sections')
    # Set the agents configuration
    agents_config = set_section_wazuh_conf(config_sections, template)
    agents_config = "".join(agents_config)
    agents_config = set_current_ip_to_agent_config(agents_config)

    yield agents_config
