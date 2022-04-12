#! /usr/bin/python3
# 2022

# Syntax: wdb-query.py <AGENT ID> <QUERY>
#         wdb-query.py global "<COMMAND> <PARAMS>"
#         wdb-query.py global "sql <QUERY>"
#
#         available global commands:
#         "insert-agent %s"
#         "insert-agent-group %s"
#         "insert-agent-belong %s"
#         "update-agent-name %s"
#         "update-agent-version %s"
#         "update-keepalive %s"
#         "update-agent-status %s"
#         "update-agent-group %s"
#         "update-fim-offset %s"
#         "update-reg-offset %s"
#         "set-labels %d %s"
#         "get-all-agents last_id %d"
#         "get-agents-by-keepalive condition %s %d last_id %d"
#         "find-agent %s"
#         "get-agent-info %d"
#         "get-labels %d"
#         "select-agent-name %d"
#         "select-agent-group %d"
#         "select-agent-status %d"
#         "select-keepalive %s %s"
#         "select-fim-offset %d"
#         "select-reg-offset %d"
#         "find-group %s"
#         "select-groups"
#         "delete-agent %d"
#         "delete-group %s"
#         "delete-agent-belong %d"
#         "delete-group-belong %s"

from socket import socket, AF_UNIX, SOCK_STREAM
from struct import pack, unpack
from sys import argv, exit
from json import dumps, loads
from json.decoder import JSONDecodeError


def db_query(agent, query):
    WDB = '/var/ossec/queue/db/wdb'
    sock = socket(AF_UNIX, SOCK_STREAM)
    sock.connect(WDB)

    msg = 'agent {0} sql {1}'.format(agent, query).encode()
    sock.send(pack("<I{0}s".format(len(msg)), len(msg), msg))

    length = unpack("<I", sock.recv(4))[0]
    return sock.recv(length).decode(errors='ignore')


def db_query_global(query):
    WDB = '/var/ossec/queue/db/wdb'

    sock = socket(AF_UNIX, SOCK_STREAM)
    sock.connect(WDB)

    msg = 'global {0}'.format(query).encode()
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
    if len(argv) < 3 or (len(argv) > 1 and argv[1] in ('-h', '--help')):
        print("Syntax: {0} <agent id> <query>")
        exit(1)
    if 'global' == argv[1]:
        response = db_query_global(argv[2])
        print(pretty(response))
    else:
        response = db_query(argv[1], ' '.join(argv[2:]))
        print(pretty(response))
