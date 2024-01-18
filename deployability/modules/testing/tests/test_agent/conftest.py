import pytest

from ..helpers import utils


@pytest.fixture()
def agent_id() -> str:
    return utils.get_client_keys()[0].get('id')
