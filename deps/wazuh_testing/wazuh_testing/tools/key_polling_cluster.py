import base64
import json
import random
import socket
import string
import struct
import sys

from cryptography.fernet import Fernet

CLIENT_KEYS = '/var/ossec/etc/lists/client.keys'
AGENT_IDS = dict()

CLUSTER_DATA_HEADER_SIZE = 20
CLUSTER_CMD_HEADER_SIZE = 12
CLUSTER_HEADER_FORMAT = '!2I{}s'.format(CLUSTER_CMD_HEADER_SIZE)
FERNET_KEY = ''.join(random.choices(string.ascii_lowercase + string.digits, k=32))
_my_fernet = Fernet(base64.b64encode(FERNET_KEY.encode()))
COUNTER = random.randrange(100000)


def cluster_msg_build(cmd: bytes = None, counter: int = None, payload: bytes = None, encrypt=True) -> bytes:
    """Build a message using cluster protocol."""
    cmd_len = len(cmd)
    if cmd_len > CLUSTER_CMD_HEADER_SIZE:
        raise Exception("Length of command '{}' exceeds limit ({}/{}).".format(cmd, cmd_len,
                                                                               CLUSTER_CMD_HEADER_SIZE))

    encrypted_data = _my_fernet.encrypt(payload) if encrypt else payload
    out_msg = bytearray(CLUSTER_DATA_HEADER_SIZE + len(encrypted_data))

    # Add - to command until it reaches cmd length
    cmd = cmd + b' ' + b'-' * (CLUSTER_CMD_HEADER_SIZE - cmd_len - 1)

    out_msg[:CLUSTER_DATA_HEADER_SIZE] = struct.pack(CLUSTER_HEADER_FORMAT, counter, len(encrypted_data), cmd)
    out_msg[CLUSTER_DATA_HEADER_SIZE:CLUSTER_DATA_HEADER_SIZE + len(encrypted_data)] = encrypted_data

    return bytes(out_msg[:CLUSTER_DATA_HEADER_SIZE + len(encrypted_data)])


def load_client_keys():
    global AGENT_IDS

    for agent in open(CLIENT_KEYS).readlines():
        try:
            line = agent.strip().split(' ')
            AGENT_IDS.update({line[0]: {'name': line[1], 'key': line[3]}})
        except (IndexError, KeyError):
            continue


def add_agent_authd_from_worker(agent_id):

    global AGENT_IDS
    agent = AGENT_IDS[agent_id]
    name = agent['name']
    key = agent['key']

    data = {
        'daemon_name': 'authd',
        'message':
            {"function": "add",
             "arguments":
                 {"name": name,
                  "ip": "any",
                  "id": agent_id,
                  "key": key,
                  "force": 0
                  }
             }
    }

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        # Create connection with socket
        sock.connect("/var/ossec/queue/cluster/c-internal.sock")

        message = cluster_msg_build(cmd=b'sendsync', counter=COUNTER, payload=json.dumps(data).encode(), encrypt=False)
        sock.sendall(message)
        response = sock.recv(4096)

        if b'"error":0' in response:
            print(json.dumps({"error": 0, "data": {"id": agent_id, "name": name, "ip": 'any', "key": key}}))
        else:
            print(response)
    except Exception as e:
        print(json.dumps({"error": 4, "message": "Could not register agent"}))
    finally:
        sock.close()


def main():
    if len(sys.argv) < 3:
        print(json.dumps({"error": 1, "message": "Too few arguments"}))
        return

    agent_id = sys.argv[2]
    load_client_keys()
    add_agent_authd_from_worker(agent_id)


if __name__ == '__main__':
    main()
