import argparse
from datetime import datetime


def get_timemstamp_from_line(line):
    return datetime.strptime(line[0:19], "%Y/%m/%d %H:%M:%S")


def callback_detect_start_scan(line):
    if 'File integrity monitoring scan started.' in line:
        return get_timemstamp_from_line(line)


def callback_detect_end_scan(line):
    if 'File integrity monitoring scan ended.' in line:
        return get_timemstamp_from_line(line)


def scan_log(file, callback):
    with open(file, 'r') as log:
        for line in log:
            cb = callback(line)
            if cb is not None:
                return cb


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-f", "--frequency", type=int, required=True, dest='frequency',
        help="Frequency of the syschek scan"
    )
    parser.add_argument(
        "-l", "--log_file", type=str, required=True, dest='ossec_log',
        help="Path to ossec.log"
    )
    args = parser.parse_args()

    end_time = scan_log(args.frequency, callback_detect_end_scan)
    start_time = scan_log(args.frequency, callback_detect_start_scan)
    assert (start_time - end_time).seconds() < (args.frequency + 10), \
        "Scan did not start in time"
