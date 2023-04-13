#! /usr/bin/python3
# September 16, 2019

# Syntax: wdb-query.py <AGENT ID> <QUERY>

from socket import socket, AF_UNIX, SOCK_STREAM
from struct import pack, unpack
from sys import argv, exit
from json import dumps, loads
from json.decoder import JSONDecodeError

def db_query(query):
    WDB = '/var/ossec/queue/db/wdb'

    sock = socket(AF_UNIX, SOCK_STREAM)
    sock.connect(WDB)

    msg = query.encode()
    sock.send(pack("<I{0}s".format(len(msg)), len(msg), msg))

    length = unpack("<I", sock.recv(4))[0]
    return sock.recv(length).decode(errors='ignore')

def pretty(response):
    if response.startswith('ok '):
        try:
            data = loads(response[3:])
            return dumps(data, indent=4)
        except JSONDecodeError:
            return response[3:]
    else:
        return response

if __name__ == "__main__":
    if len(argv) < 2 or (len(argv) > 1 and argv[1] in ('-h', '--help')):
        print("Syntax: {0} <query>")
        exit(1)

    response = db_query(' '.join(argv[1:]))
    print(pretty(response))
