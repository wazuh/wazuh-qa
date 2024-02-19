#! /usr/bin/env python3
# November 18th 2020

# Syntax: wdb-query.py <socket>

from socket import socket, AF_UNIX, SOCK_STREAM
from struct import pack, unpack
from sys import argv, exit, stdin
import signal
import argparse
import time


def signal_handler(sig, frame):
    print("Signal received. Exiting...")
    exit(0)


def db_query(agent):
    WDB = '/var/ossec/queue/db/wdb'
    sock = socket(AF_UNIX, SOCK_STREAM)
    sock.connect(WDB)

    query = f"agent {agent} sql UPDATE fim_entry SET checksum='corruptchecksum'".encode()
    payload = pack("<I{0}s".format(len(query)), len(query), query)
    sock.send(payload)

    length = unpack("<I", sock.recv(4))[0]
    response = sock.recv(length)

    sock.close()


def main(interval, duration, agents):
    start_time = time.time()

    while (time.time() - start_time) < duration:
        for agent in agents:
            db_query(agent)
        time.sleep(interval)


if __name__ == "__main__":

    signal.signal(signal.SIGINT, signal_handler)

    parser = argparse.ArgumentParser(description='File manipulation script')
    parser.add_argument('-i', '--interval', dest='time_step', type=float, required=True, action='store',
                        help='Type the time between queries.')
    parser.add_argument('-d', '--duration', dest='duration', type=float, required=True, action='store',
                        help='Duration of script execution in seconds')
    parser.add_argument('-a', '--agents', dest='agents', required=False, type=str, nargs='+', action='store',
                        default=None, help='Type the agents id to monitor separated by whitespace.')

    args = parser.parse_args()

    main(args.interval, args.duration, args.agents)
