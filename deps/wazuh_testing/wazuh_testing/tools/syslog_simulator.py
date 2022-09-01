import threading
import logging

from logging.handlers import SysLogHandler
from sys import getsizeof
from time import sleep


class Syslogger:
    """Class that allows sending syslog messages.

    Args:
        message (str): Message to send.
        num_messages (int): Number of messages to send.
        fixed_message_size (int): Message size (KB).
        interval_burst_time (int): Waiting time for sending a new group of messages (seconds).
        num_messages_per_burst (int): Number of messages to send per burst.

    Attributes:
        syslogger (logging.Logger): Logger object used for building syslog messages.
        message (str): Message to send.
        num_messages (int): Number of messages to send.
        fixed_message_size (int): Message size (KB).
        interval_burst_time (int): Waiting time for sending a new group of messages (seconds).
        num_messages_per_burst (int): Number of messages to send per burst.
    """
    def __init__(self, message, num_messages, fixed_message_size, interval_burst_time, num_messages_per_burst):
        self.syslogger = logging.getLogger()
        self.syslogger.setLevel(logging.DEBUG)
        handler = SysLogHandler(address='/dev/log')
        formatter = logging.Formatter(fmt='%(message)s')
        handler.setFormatter(formatter)
        self.syslogger.addHandler(handler)
        self.message = message
        self.num_messages = num_messages
        self.fixed_message_size = fixed_message_size * 1024 if fixed_message_size is not None else None
        self.interval_burst_time = interval_burst_time
        self.num_messages_per_burst = num_messages_per_burst

    def send_syslog_messages(self, message):
        """Send syslog messages"""
        self.syslogger.debug(message)

    def run_module(self):
        """Send syslog messages according to the input parameters"""
        sent_messages = 0
        sent_messages_burst = 0
        while self.num_messages != 0 and sent_messages < self.num_messages:
            message = f"{self.message} {sent_messages}"
            # Add dummy chars if the message size is not reachead
            if self.fixed_message_size is not None:
                event_msg_size = getsizeof(message)
                dummy_message_size = self.fixed_message_size - event_msg_size
                char_size = getsizeof(message[0]) - getsizeof('')
                message += 'A' * (dummy_message_size//char_size)
            # Create interval between messages to simulate burst of messages
            if self.interval_burst_time != 0 and self.num_messages_per_burst != 0:
                if sent_messages_burst < self.num_messages_per_burst:
                    sent_messages_burst += 1
                else:
                    sleep(self.interval_burst_time)
                    sent_messages_burst = 1
            # Send message
            self.send_syslog_messages(message)
            sent_messages += 1

    def start(self):
        thread = threading.Thread(target=self.run_module)
        # Starting threads
        thread.start()
        # Wait until all threads finish
        thread.join()
