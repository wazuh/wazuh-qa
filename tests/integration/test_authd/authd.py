import re


DAEMON_NAME = 'wazuh-authd'


def validate_authd_response(response, expected):
    response = response.split(sep=" ", maxsplit=1)
    status = response[0]
    if expected['status'] == 'success':
        assert status == 'OSSEC', 'Invalid status response'
        agent_key = response[1].split('\'')[1::2][0].split()
        id = agent_key[0]
        name = agent_key[1]
        ip = agent_key [2]
        key = agent_key[3]
        if 'id' in expected:
            assert id == expected['id'], 'Invalid id response'
        if 'name' in expected:
            assert name == expected['name'], 'Invalid name response'
        if 'ip' in expected:
            assert ip == expected['ip'], 'Invalid ip response'
        if 'key' in expected:
            assert key == expected['key'], 'Invalid key response'

    elif expected['status'] == 'error':
        assert status == "ERROR:"
        message = response[1]
        if 'message' in expected:
            assert re.match(expected['message'], message), 'Invalid error message response'

    else:
        raise Exception('Invalid expected status')
