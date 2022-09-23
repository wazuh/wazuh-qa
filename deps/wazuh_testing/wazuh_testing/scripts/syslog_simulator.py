import socket
import argparse
import sys
import logging
import time


TCP = 'tcp'
UDP = 'udp'
DEFAULT_MESSAGE = 'Login failed: admin, test'
LOGGER = logging.getLogger('syslog_simulator')
TCP_LIMIT = 1000
UDP_LIMIT = 200


def set_logging(debug=False):
    LOGGER.setLevel(logging.DEBUG if debug else logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(asctime)s — %(levelname)s — %(message)s"))
    LOGGER.addHandler(handler)


def validate_parameters(parameters):
    protocol_limit = TCP_LIMIT if parameters.protocol == TCP else UDP_LIMIT

    if parameters.messages_number <= 0:
        LOGGER.error(f"The number of messages parameter has to be greater than 0")
        return sys.exit(1)

    if parameters.eps > 0 and parameters.eps > protocol_limit:
        LOGGER.error(f"You can't select eps greather than {protocol_limit}")
        return sys.exit(1)


def get_parameters():
    arg_parser = argparse.ArgumentParser()

    arg_parser.add_argument('-n', '--messages-number', metavar='<messages_number>', type=int,
                            help='Number of messages to send', required=True, default=0,
                            dest='messages_number')

    arg_parser.add_argument('-m', '--message', metavar='<message>', type=str,
                            help='Message to send', required=False, default=DEFAULT_MESSAGE,
                            dest='message')

    arg_parser.add_argument('-a', '--address', metavar='<address>', type=str,
                            help='Sender IP address', required=False, default='localhost',
                            dest='address')

    arg_parser.add_argument('-p', '--port', metavar='<port>', type=int,
                            help='Sender destination port', required=False, default=514,
                            dest='port')

    arg_parser.add_argument('--protocol', metavar='<protocol>', type=str,
                            help='Sender protocol', required=False, default='tcp', choices=['tcp', 'udp'],
                            dest='protocol')

    arg_parser.add_argument('-e', '--eps', metavar='<eps>', type=int,
                            help='Event per second', required=False, default=-1, dest='eps')

    arg_parser.add_argument('-d', '--debug', action='store_true', required=False, help='Activate debug logging')

    return arg_parser.parse_args()


def send_messages(message, num_messages, eps, address='locahost', port=514, protocol=TCP):
    sent_messages = 0
    custom_message = f"{message}\n" if message[-1] != '\n' not in message else message
    protocol_limit = TCP_LIMIT if protocol == TCP else UDP_LIMIT
    speed = eps if eps > 0 else protocol_limit

    LOGGER.info(f"Sending {num_messages} to {address}:{port} via {protocol.upper()} ({speed}/s)")

    # Create socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM if protocol == TCP else socket.SOCK_DGRAM)
    if protocol == TCP:
        sock.connect((address, port))

    try:
        # Get initial time
        initial_batch_time = time.time()
        start_batch_time = time.time()

        # Send the specified number messages
        while sent_messages < num_messages:
            if protocol == TCP:
                sock.send(custom_message.encode())
            else:
                sock.sendto(custom_message.encode(), (address, port))
            sent_messages += 1

            # Wait until next batch
            if sent_messages % speed == 0:
                time.sleep(1 - (time.time() - start_batch_time))
                start_batch_time = time.time()

        LOGGER.info(f"Sent {sent_messages} messages in {round(time.time() - initial_batch_time, 0)}s")
    finally:
        sock.close()


def main():
    parameters = get_parameters()
    set_logging(parameters.debug)
    validate_parameters(parameters)

    send_messages(parameters.message, parameters.messages_number, parameters.eps, parameters.address, parameters.port,
                  parameters.protocol)


if __name__ == "__main__":
    main()
