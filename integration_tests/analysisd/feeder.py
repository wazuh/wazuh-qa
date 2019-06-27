#!/usr/bin/env python
# Print messages on OSSEC queue (analysisd/agentd)
# November 1, 2016
#
# Syntax: queue.py <message>
# Standard message form: <id>:<location>:<log>

from socket import socket, AF_UNIX, SOCK_DGRAM, SO_SNDBUF, SOL_SOCKET
import sys

def feeding(basedir, msg, limit=200):
    ADDR = basedir + '/queue/ossec/queue'
    BLEN = 212992

    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(ADDR)

    oldbuf = sock.getsockopt(SOL_SOCKET, SO_SNDBUF)

    if oldbuf < BLEN:
        sock.setsockopt(SOL_SOCKET, SO_SNDBUF, BLEN)
        newbuf = sock.getsockopt(SOL_SOCKET, SO_SNDBUF)
        print("INFO: Buffer expended from {0} to {1}".format(oldbuf, newbuf))

    string = ' '.join(msg)
    i=1

    while i < limit:
        sock.send(string.encode())
        i += 1

    sock.close()
