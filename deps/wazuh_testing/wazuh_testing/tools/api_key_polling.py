import json
import sys
from base64 import b64encode

import requests
from urllib3 import disable_warnings, exceptions

disable_warnings(exceptions.InsecureRequestWarning)

HOST = MASTER_NODE_IP
PORT = 55000
BASE_URL = f'https://{HOST}:{PORT}'
WAZUH_PATH = '/var/ossec'
CLIENT_KEYS = '/var/ossec/etc/lists/client.keys'
AGENT_IDS = dict()


def login_headers(user='wazuh', password='wazuh'):
    basic_auth = f'{user}:{password}'.encode()
    return {'Content-Type': 'application/json',
            'Authorization': f'Basic {b64encode(basic_auth).decode()}'}


def auth_headers(token):
    return {'Content-Type': 'application/json',
            'Authorization': f'Bearer {token}'}


def insert_agent_manual(agent_id):
    global AGENT_IDS
    agent = AGENT_IDS[agent_id]
    name = agent['name']
    key = agent['key']

    response = requests.get(f'{BASE_URL}/security/user/authenticate', headers=login_headers(), verify=False)
    token = response.json()['data']['token']

    response = requests.post(f'{BASE_URL}/agents/insert', headers=auth_headers(token),
                             json={
                                 'name': name,
                                 'ip': 'any',
                                 'id': agent_id,
                                 'key': key
                             },
                             verify=False)
    if response.status_code == 200:
        print(json.dumps({"error": 0, "data": {"id": agent_id, "name": name, "ip": 'any', "key": key}}))
    else:
        print(json.dumps({"error": 4, "message": "No agent key found"}))


def load_client_keys():
    global AGENT_IDS

    for agent in open(CLIENT_KEYS).readlines():
        try:
            line = agent.split(' ')
            AGENT_IDS.update({line[0]: {'name': line[1], 'key': line[2]}})
        except (IndexError, KeyError):
            continue


def main():
    if len(sys.argv) < 3:
        print(json.dumps({"error": 1, "message": "Too few arguments"}))
        return

    agent_id = sys.argv[2]
    load_client_keys()
    insert_agent_manual(agent_id)


if __name__ == '__main__':
    main()
