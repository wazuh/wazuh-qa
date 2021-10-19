import pytest

from wazuh_testing.tools.agent_simulator import create_agents


@pytest.fixture(scope="function")
def configure_agents(request, get_configuration):
    metadata = get_configuration.get('metadata')
    agents_number = metadata['agents_number']
    SERVER_ADDRESS = getattr(request.module, 'SERVER_ADDRESS')
    CRYPTO = getattr(request.module, 'CRYPTO')

    agents = create_agents(agents_number, SERVER_ADDRESS, CRYPTO, agents_os=metadata['agents_os'],
                           agents_version=metadata['agents_version'])
    setattr(request.module, 'agents', agents)
