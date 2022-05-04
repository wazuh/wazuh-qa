from base64 import b64encode
from json import dumps
from os.path import join, exists, dirname, abspath
from secrets import token_hex
from sys import argv

import requests
from urllib3 import disable_warnings, exceptions

disable_warnings(exceptions.InsecureRequestWarning)

HOST = 'MASTER_NODE_IP'
PORT = 55000
BASE_URL = f'https://{HOST}:{PORT}'
TOKEN_FILE = join(dirname(abspath(__file__)), '.api_token')


def login_headers(user='wazuh', password='wazuh'):
    basic_auth = f'{user}:{password}'.encode()
    return {'Content-Type': 'application/json',
            'Authorization': f'Basic {b64encode(basic_auth).decode()}'}


def auth_headers(token):
    return {'Content-Type': 'application/json',
            'Authorization': f'Bearer {token}'}


def insert_agent_manual(token, agent_id=None, agent_ip=None, agent_name=None, agent_key=None):
    try:
        response = requests.post(f'{BASE_URL}/agents/insert', headers=auth_headers(token),
                                 json={
                                     'name': agent_name,
                                     'ip': agent_ip,
                                     'id': agent_id,
                                     'key': agent_key
                                 },
                                 verify=False)

        if response.status_code == 200:
            print(dumps(
                {"error": 0, "data": {"id": agent_id, "name": agent_name, "ip": agent_ip, "key": agent_key}}))
        elif response.status_code == 401:
            insert_agent_manual(read_token(new_token=True), agent_id, agent_ip, agent_name, agent_key)
        else:
            print(dumps({"error": 4, "message": "Could not register agent"}))

    except Exception as e:
        print(dumps({"error": 5, "message": str(e)}))


def read_token(new_token=False):
    def obtain_token():
        response = requests.post(f"{BASE_URL}/security/user/authenticate", headers=login_headers(), verify=False)
        return response.json()['data']['token']

    if not exists(TOKEN_FILE) or new_token:
        token = obtain_token()
        with open(TOKEN_FILE, 'w') as f:
            f.write(token)

        return token

    return open(TOKEN_FILE).read().strip()


def get_agent_info(agent_id):
    # Retrieve agent information here and return a dict
    return {'agent_id': agent_id,
            'agent_name': f'test_agent_{agent_id}',
            'agent_ip': 'any',
            'agent_key': token_hex(32)}


def main():
    if len(argv) < 3:
        print(dumps({"error": 1, "message": "Too few arguments"}))
        return

    agent_id = argv[2]
    insert_agent_manual(read_token(), **get_agent_info(agent_id))


if __name__ == '__main__':
    main()
