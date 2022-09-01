import argparse

from wazuh_testing.tools.syslog_simulator import Syslogger


def main():
    arg_parser = argparse.ArgumentParser()

    arg_parser.add_argument('-m', '--message', metavar='<message>', type=str, required=True,
                            default='Login failed: admin, test message, Message number:',
                            help="The syslog message", dest='message')

    arg_parser.add_argument('-e', '--num-messages', metavar='<num_messages>', type=int,
                            help='Set the amount of message to be sent.',
                            required=False, default=0, dest='num_messages')

    arg_parser.add_argument('-f', '--fixed-message-size', metavar='<fixed_message_size>', type=int, required=False,
                            default=None, help='Size of all the agent modules messages (KB)', dest='fixed_message_size')

    arg_parser.add_argument('-t', '--interval-burst-time', metavar='<interval_burst_time>', dest='interval_burst_time',
                            type=int, required=False, default=0,
                            help='Interval time in seconds for the messages burst')

    arg_parser.add_argument('-b', '--num-messages-per-burst', metavar='<num_messages_per_burst>',
                            dest='num_messages_per_burst', type=int, required=False, default=0,
                            help='Number of messages to send per burst')

    args = arg_parser.parse_args()

    syslogger = Syslogger(args.message, args.num_messages, args.fixed_message_size, args.interval_burst_time,
                          args.num_messages_per_burst)

    syslogger.start()


if __name__ == "__main__":
    main()
