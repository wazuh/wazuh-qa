#!/usr/bin/env python
# Print messages on OSSEC queue (analysisd/agentd)
# November 1, 2016
#
# Syntax: queue.py <message>
# Standard message form: <id>:<location>:<log>

from socket import socket, AF_UNIX, SOCK_DGRAM, SO_SNDBUF, SOL_SOCKET
from sys import argv

ADDR = '/var/ossec/queue/ossec/queue'
BLEN = 212992

if len(argv) < 3:
    print("Syntax: {0} [-L] <message> <N messages>")
    exit(1)

sock = socket(AF_UNIX, SOCK_DGRAM)
sock.connect(ADDR)
oldbuf = sock.getsockopt(SOL_SOCKET, SO_SNDBUF)

if oldbuf < BLEN:
    sock.setsockopt(SOL_SOCKET, SO_SNDBUF, BLEN)
    newbuf = sock.getsockopt(SOL_SOCKET, SO_SNDBUF)
    print("INFO: Buffer expended from {0} to {1}".format(oldbuf, newbuf))

if argv[1] == '-L':
    string = ' '.join(argv[2:])
    i=1
    limit = 100
    limit = int(argv[3])
    try:
        while i<limit:
            sock.send(string.encode())
            i += 1
    except BaseException as e:
        print(e)
        print("Messages: {0}\nBytes: {1}".format(i, i * len(string)))

else:
    string = ' '.join(argv[1:])
    sock.send(string.encode())

sock.close()