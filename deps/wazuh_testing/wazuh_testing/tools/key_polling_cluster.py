import socket
from base64 import b64encode
from json import dumps
from os.path import join
from random import choices, randrange
from secrets import token_hex
from socket import socket, AF_UNIX, SOCK_STREAM
from string import ascii_lowercase, digits
from struct import pack
from sys import argv

from cryptography.fernet import Fernet

CLUSTER_DATA_HEADER_SIZE = 20
CLUSTER_CMD_HEADER_SIZE = 12
CLUSTER_HEADER_FORMAT = '!2I{}s'.format(CLUSTER_CMD_HEADER_SIZE)
WAZUH_PATH = '/var/ossec'
FERNET_KEY = ''.join(choices(ascii_lowercase + digits, k=32))
_my_fernet = Fernet(b64encode(FERNET_KEY.encode()))
COUNTER = randrange(100000)


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

    out_msg[:CLUSTER_DATA_HEADER_SIZE] = pack(CLUSTER_HEADER_FORMAT, counter, len(encrypted_data), cmd)
    out_msg[CLUSTER_DATA_HEADER_SIZE:CLUSTER_DATA_HEADER_SIZE + len(encrypted_data)] = encrypted_data

    return bytes(out_msg[:CLUSTER_DATA_HEADER_SIZE + len(encrypted_data)])


def get_agent_info(agent_id):
    # Retrieve agent information here and return a dict
    return {'agent_id': agent_id,
            'agent_name': f'test_agent_{agent_id}',
            'agent_ip': 'any',
            'agent_key': token_hex(32)}


def add_agent_authd_from_worker(agent_id=None, agent_ip=None, agent_name=None, agent_key=None):
    data = {
        'daemon_name': 'authd',
        'message':
            {"function": "add",
             "arguments":
                 {"name": agent_name,
                  "ip": agent_ip,
                  "id": agent_id,
                  "key": agent_key,
                  "force": -1
                  }
             }
    }

    sock = socket(AF_UNIX, SOCK_STREAM)
    try:
        # Create connection with socket
        sock.connect(join(WAZUH_PATH, "queue/cluster/c-internal.sock"))

        message = cluster_msg_build(cmd=b'sendsync', counter=COUNTER, payload=dumps(data).encode(), encrypt=False)
        sock.sendall(message)
        response = sock.recv(4096)

        if b'"error":0' in response:
            print(dumps({"error": 0, "data": {"id": agent_id, "name": agent_name, "ip": agent_ip, "key": agent_key}}))
        else:
            print(response)
    except Exception:
        print(dumps({"error": 4, "message": "Could not register agent"}))
    finally:
        sock.close()


def main():
    if len(argv) < 3:
        print(dumps({"error": 1, "message": "Too few arguments"}))
        return

    agent_id = argv[2]
    add_agent_authd_from_worker(**get_agent_info(agent_id))


if __name__ == '__main__':
    main()
