import argparse
from datetime import datetime
import sys


def get_timemstamp_from_line(line):
    """
        Extracts timestam from ossec.log lines
        :param str line: line of ossec.log
        :return: Returns a timestamp in the form 2020/03/02 13:07:32
    """
    return datetime.strptime(line[0:19], "%Y/%m/%d %H:%M:%S")


def callback_detect_start_scan(line):
    """
        Checks if line contains the start of scan sting
        :param str line: line of ossec.log
        :return: Timestamp in the line
    """
    if 'File integrity monitoring scan started.' in line:
        return get_timemstamp_from_line(line)


def callback_detect_end_scan(line):
    """
        Checks if line contains the end of scan sting
        :param str line: line of ossec.log
        :return: Timestamp in the line
    """
    if 'File integrity monitoring scan ended.' in line:
        return get_timemstamp_from_line(line)


def scan_log(file, frequency, n_scans):
    """
        Reads ossec.log file and checks if the scans are hppening
            with the correct frequency
        :param str file: path to ossec.log
        :param str frequency: Frequency of the scan
        :param str n_scans: Minimum number of scans that we expect
        :return: None
    """
    time_start = None
    time_end = None
    scan_finished = False
    scan_count = 0
    upper_bound = frequency + (1 + int(frequency*0.05))
    lower_bound = frequency - (1 + int(frequency*0.05))
    with open(file, 'r') as log:
        first_start = None
        for line in log:
            if first_start is None:
                first_start = callback_detect_start_scan(line)
            else:
                if callback_detect_end_scan(line) is not None:
                    time_end = get_timemstamp_from_line(line)
                if callback_detect_start_scan(line) is not None:
                    time_start = get_timemstamp_from_line(line)
                if time_end is not None and time_start is not None:
                    scan_finished = True
                    scan_count += 1
                    time_diff = (time_start - time_end).total_seconds()
                    assert (lower_bound <= time_diff <= upper_bound), "\
                        Scan not finished in time.\n\
                        Frequency: {}\n\
                        Last scan end: {}\n\
                        Current scan start: {}\n\
                        Time difference: {}".format(
                            frequency, time_end, time_start, time_diff
                        )
                    time_start = None
                    time_end = None
    assert scan_finished, "\
        No scan finished\n\
        Last scan end: {}\n\
        Current scan start: {}\n".format(
            time_end, time_start
        )
    assert n_scans <= scan_count, \
        "The number of scans is less than expected:\n\
        Expected scans: {}\n\
        Number of scans: {}\n".format(n_scans, scan_count)


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
    parser.add_argument(
        "-e", "--expected_scans", type=int, required=True, dest='exp_scans',
        help="Path to ossec.log"
    )
    args = parser.parse_args()
    scan_log(args.ossec_log, args.frequency, args.exp_scans)


if __name__ == "__main__":
    sys.exit(main())
