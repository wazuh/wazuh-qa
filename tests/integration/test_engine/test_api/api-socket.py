import socket
import json

with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as socket_client:
    socket_client.connect('/var/ossec/queue/sockets/engine-api')
    message = r'''
    {
        "version": 1,
        "command": "get_catalog",
        "origin": {
            "name": "engine-schema",
            "module": "engine"
        },
        "parameters": {
            "name": "environment/wazuh/0",
            "format": "yaml"
        }
    }
    '''
    message = json.dumps(json.loads(message))
    msg_size = len(message)
    
    # request format: message_size(little) + encoded_message
    api_request = msg_size.to_bytes(4, 'little') + bytes(message, 'UTF-8')
    socket_client.sendall(api_request)

    # It has to be the highest UDP package possible size
    data = socket_client.recv(65507)

    resp_size = int.from_bytes(data[:4], 'little')
    resp_message = data[4:resp_size+4].decode('UTF-8')

    print(f"Response size: {resp_size}")
    print(f"Response: {resp_message}")