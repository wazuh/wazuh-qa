import pytest

from ..helpers import utils
from ..helpers.wazuh_api.api import WazuhAPI


@pytest.fixture(scope='module')
def agent_id() -> str:
    agent_id = utils.get_client_keys()[0].get('id')

    yield agent_id


@pytest.fixture(scope='module')
def agent_info(wazuh_api: WazuhAPI) -> str:
    agent_id = utils.get_client_keys()[0].get('id')
    agent_info = wazuh_api.get_agent(agent_id)

    yield agent_info
