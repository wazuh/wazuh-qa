import os
import sys

import argparse
import logging
from datetime import datetime


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

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler("check_scheduled_scan.log", mode='a'),
            logging.StreamHandler()
        ]
    )
    # Logging and error messages
    error_scan_timeout_message = "ERROR: Scan not finished in time.\n"
    error_last_scan_timeout_message = "ERROR: Last scan not \
        finished in time.\n"
    log_scan_message = "Scan {}:\n"
    log_wait_scan_message = "Wait to finnish last scan"
    info_message = "Frequency: {}\n\
        Last scan end: {}\n\
        Current scan start: {}\n\
        Time difference: {}"
    error_no_scan_message = "No scan finished\n\
        Last scan end: {}\n\
        Current scan start: {}\n"
    error_minimum_scan_message = "The number of scans is less than expected:\n\
        Expected scans: {}\n\
        Number of scans: {}\n"

    time_start = None
    time_end = None
    scan_finished = False
    scan_count = 0
    upper_bound = frequency + (1 + int(frequency*0.05))
    lower_bound = frequency - (1 + int(frequency*0.05))
    logging.info(
        "Start Log monitor"
    )
    try:
        with open(file, 'r') as log:
            first_start = None
            logging.info(
                "Check if all the scans started in time"
            )
            for line in log:
                if first_start is None:
                    first_start = callback_detect_start_scan(line)
                else:
                    if time_end is None:
                        time_end = callback_detect_end_scan(line)
                    if time_start is None:
                        time_start = callback_detect_start_scan(line)
                    if time_end is not None and time_start is not None:
                        scan_finished = True
                        scan_count += 1
                        time_diff = (time_start - time_end).total_seconds()
                        logging.info(
                            log_scan_message.format(scan_count) +
                            info_message.format(
                                frequency, time_end, time_start, time_diff
                            )
                        )
                        assert (lower_bound <= time_diff <= upper_bound), \
                            error_scan_timeout_message + \
                            info_message.format(
                                frequency, time_end, time_start, time_diff
                            )
                        time_start = None
                        time_end = None
            if time_end is not None and time_start is None:
                logging.info(log_wait_scan_message)
                size = os.stat(file).st_size
                while time_start is None:
                    size_new = os.stat(file).st_size
                    if size < size_new:
                        size = size_new
                        log.seek(0)
                        time_start = callback_detect_start_scan(
                            log.readlines()[-1]
                        )
                        elapsed_time = (
                            datetime.now() - time_end
                        ).total_seconds()
                        assert elapsed_time < upper_bound, \
                            error_last_scan_timeout_message + \
                            info_message.format(
                                frequency, time_end, time_start, elapsed_time
                            )

                if time_start is not None:
                    scan_finished = True
                    time_diff = (time_start - time_end).total_seconds()
                    assert (lower_bound <= time_diff <= upper_bound), \
                        error_last_scan_timeout_message + \
                        info_message.format(
                            frequency, time_end, time_start, time_diff
                        )

        assert scan_finished, \
            error_no_scan_message.format(
                time_end, time_start
            )
        assert n_scans <= scan_count, \
            error_minimum_scan_message.format(n_scans, scan_count)
    except AssertionError as asertion_error:
        logging.error(asertion_error)
        raise asertion_error
    except Exception as exception:
        logging.critical("An error has ocurred. Exiting\n" + repr(exception))
        raise Exception


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
        help="Minimum number of expected scans"
    )
    args = parser.parse_args()
    scan_log(args.ossec_log, args.frequency, args.exp_scans)


if __name__ == "__main__":
    sys.exit(main())
