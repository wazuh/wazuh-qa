import socket
import struct
import sys
import time


def main():
    """Desynchronize agents in the worker's global.db. To use the script, pass three arguments indicating the first
    agent ID, the last agent ID from the range of agents to be added to the default group; and the node name.

    The script updates the global.db agent table entries where ID is one in the range specified. This update includes
    setting the node_name and the agent version. After that, each agent is marked as required to be synchronized
    (synreq) every 10 seconds.

    This script must be used in a Wazuh worker node.
    """

    def send_msg(msg):
        """Send message to a socket.

        Args:
            msg (str): Message to be sent to the socket.
        """
        msg = struct.pack('<I', len(msg)) + msg.encode()

        # Send msg
        sock.send(msg)

        # Receive response
        data = sock.recv(4)
        data_size = struct.unpack('<I', data[0:4])[0]
        data = sock.recv(data_size).decode(encoding='utf-8', errors='ignore').split(" ", 1)

        return data

    if len(sys.argv) != 4:
        msg = f"unsync.py <first_id> <last_id> <node_name> (you used {' '.join(sys.argv)})"
        print(msg)
        exit(1)

    first_id = min(int(sys.argv[1]), int(sys.argv[2]))
    last_id = max(int(sys.argv[1]), int(sys.argv[2]))
    node_name = sys.argv[3]

    ADDR = '/var/ossec/queue/db/wdb'

    while True:
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(ADDR)
            msg = f'global sql UPDATE agent SET node_name = "{node_name}", version="Wazuh v4.0.0" ' \
                  f'where id>{first_id} and id<={last_id}'
            print(f"Updating node_name ({node_name}) and version of the agents: {send_msg(msg)}")
            sock.close()
            break
        except Exception as e:
            print(f"Could not find wdb socket: {e}. Retrying in 10 seconds...")
            time.sleep(10)

    while True:
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(ADDR)
            msg = f'global sql UPDATE agent SET sync_status="syncreq", last_keepalive="{int(time.time())}", ' \
                  f'connection_status="active" where id>{first_id} and id<={last_id}'
            print(f"Updating sync_status of agents between {first_id} and {last_id}: {send_msg(msg)}")
            sock.close()
            time.sleep(10)
        except KeyboardInterrupt:
            print("Closing socket")
            sock.close()
            exit(1)
        except Exception as e:
            print(f"An exception was raised: {e}. Retrying in 10 seconds...")
            time.sleep(10)


if __name__ == '__main__':
    main()
