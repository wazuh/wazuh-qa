import argparse
import logging
import logging.handlers
from logging.handlers import SysLogHandler
from time import sleep
from sys import getsizeof

class CreateSyslogger:
    """Class that allows sending syslog messages.

    Args:
        args (argparse.Namespace): Script args.
    """
    def __init__(self, args):
        self.syslogger = logging.getLogger()
        self.syslogger.setLevel(logging.DEBUG)
        self.handler = SysLogHandler(address='/dev/log')
        self.formatter = logging.Formatter(fmt='%(message)s')
        self.handler.setFormatter(self.formatter)
        self.syslogger.addHandler(self.handler)
        self.message = args.message
        self.total_msg = args.total_msg
        self.fixed_message_size = args.fixed_message_size * 1024 if args.fixed_message_size is not None else None
        self.interval_burst_time = args.interval_burst_time
        self.messages_per_burst = args.messages_per_burst

    def send_syslog_messages(self, message):
        """Send syslog messages"""
        self.syslogger.debug(message)

    def run_module(self):
        """Send syslog messages according to the input parameters"""
        sent_messages = 0
        sent_messages_burst = 0
        while self.total_msg is not None and sent_messages < self.total_msg:
            message = f"{self.message} {sent_messages}"
            # Add dummy chars if the message size is not reachead
            if self.fixed_message_size is not None:
                    event_msg_size = getsizeof(message)
                    dummy_message_size = self.fixed_message_size - event_msg_size
                    char_size = getsizeof(message[0]) - getsizeof('')
                    message += 'A' * (dummy_message_size//char_size)
            # Create interval between messages to simulate burst of messages
            if self.interval_burst_time is not None and self.messages_per_burst is not None:
                if sent_messages_burst < self.messages_per_burst:
                    sent_messages_burst += 1
                else:
                    sleep(self.interval_burst_time)
                    sent_messages_burst = 1
            # Send message
            self.send_syslog_messages(message)
            sent_messages += 1


def main():
    arg_parser = argparse.ArgumentParser()

    arg_parser.add_argument('-m', '--message', metavar='<message>', type=str, required=True,
                            default='Login failed: admin, test message, Message number:',
                            help="The syslog message", dest='message')

    arg_parser.add_argument('-e', '--total-msg', metavar='<total_msg>', type=int,
                            help='Limit the amount of message to be sent.',
                            required=False, default=None, dest='total_msg')

    arg_parser.add_argument('-f', '--fixed-message-size', metavar='<fixed_message_size>', type=int, required=False,
                            default=None, help='Size of all the agent modules messages (KB)', dest='fixed_message_size')

    arg_parser.add_argument('-t', '--interval-burst-time', metavar='<interval_burst_time>', dest='interval_burst_time',
                            type=int, required=False, default=None,
                            help='Interval time in seconds for the messages burst')

    arg_parser.add_argument('-b', '--messages-per-burst', metavar='<messages_per_burst>', dest='messages_per_burst',
                            type=int, required=False, default=None,
                            help='Total messages per burst burst')

    args = arg_parser.parse_args()

    syslogger = CreateSyslogger(args)
    syslogger.run_module()


if __name__ == "__main__":
    main()
