#! /usr/bin/env python3
# November 18th 2020

# Syntax: wdb-query.py <socket>

from socket import socket, AF_UNIX, SOCK_STREAM
from struct import pack, unpack
from sys import argv, exit, stdin, stdout


def db_query(query):
    WDB = '/var/ossec/queue/db/wdb'
    sock = socket(AF_UNIX, SOCK_STREAM)
    sock.connect(WDB)

    query = query.encode()
    payload = pack("<I{0}s".format(len(query)), len(query), query)
    sock.send(payload)

    length = unpack("<I", sock.recv(4))[0]
    response = sock.recv(length)
    stdout.buffer.write(response)

    sock.close()


if __name__ == "__main__":
    if len(argv) < 2 or argv[1] in ('-h', '--help'):
        print("Syntax: {0} <socket>".format(argv[0]))
        exit(1)

    db_query(argv[1])

    if stdout.isatty():
        print("")
