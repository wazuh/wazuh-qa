import json
import re
import secrets
import subprocess
import sys
from base64 import b64encode
from os.path import join, exists, dirname, abspath

import requests
from urllib3 import disable_warnings, exceptions

disable_warnings(exceptions.InsecureRequestWarning)

HOST = 'MASTER_NODE_IP'
PORT = 55000
BASE_URL = f'https://{HOST}:{PORT}'
WAZUH_PATH = '/var/ossec'
CLIENT_KEYS = '/var/ossec/etc/lists/client.keys'
AGENT_IDS = dict()
TOKEN_FILE = join(dirname(abspath(__file__)), '.api_token')
TOTAL_AGENTS = 8000
N_WORKERS = 25
ITERATIONS = 3


def login_headers(user='wazuh', password='wazuh'):
    basic_auth = f'{user}:{password}'.encode()
    return {'Content-Type': 'application/json',
            'Authorization': f'Basic {b64encode(basic_auth).decode()}'}


def auth_headers(token):
    return {'Content-Type': 'application/json',
            'Authorization': f'Bearer {token}'}


def current_worker():
    regex = r'Test_cluster_performance_[\w\d]+_manager_(\d+)'
    output = subprocess.check_output(['grep', 'node_name', '/var/ossec/etc/ossec.conf']).decode().strip()
    return int(re.search(regex, output).group(1))


def insert_agent_manual(agent_id, token):
    name = f'new_agent_added_with_id_{agent_id}'
    key = secrets.token_hex(32)

    response = requests.post(f'{BASE_URL}/agents/insert', headers=auth_headers(token),
                             json={
                                 'name': name,
                                 'ip': 'any',
                                 'id': agent_id,
                                 'key': key
                             },
                             verify=False)
    if response.status_code == 200:
        print(json.dumps({"id": agent_id, "name": name, "ip": 'any', "key": key}))
    elif response.status_code == 401:
        insert_agent_manual(agent_id, read_token(new_token=True))
    else:
        print(json.dumps({"error": 1, "message": f"Could not register {agent_id}"}))


def obtain_token():
    response = requests.get(f'{BASE_URL}/security/user/authenticate', headers=login_headers(), verify=False)
    return response.json()['data']['token']


def read_token(new_token=False):
    if not exists(TOKEN_FILE) or new_token:
        token = obtain_token()
        with open(TOKEN_FILE, 'w') as f:
            f.write(token)

        return token

    return open(TOKEN_FILE).read().strip()


def main():
    current_iteration = int(sys.argv[1])
    n_agents = TOTAL_AGENTS // (N_WORKERS * ITERATIONS)
    min_range = n_agents * (current_worker() - 1) * ITERATIONS + current_iteration * n_agents

    for i in range(min_range, min_range + n_agents):
        insert_agent_manual(str(i).zfill(3), obtain_token())


if __name__ == '__main__':
    main()
