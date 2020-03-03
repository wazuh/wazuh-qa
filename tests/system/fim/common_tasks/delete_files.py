# Copyright (C) 2015-2020, Wazuh Inc.
# All rights reserved.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.


import argparse
import random
import logging
import os
import time


def delete_file(path, attempt=0, sleep_time=5.0):
    success = True
    try:
        if attempt > 0:
          time.sleep(sleep_time)
          logging.info(f"Failed to delete {path}, retry: {attempt}")
        if attempt > 10:
          return False
        open(path, 'a').close() # (To update mtime_after)
        os.remove(path)
    except FileNotFoundError as e:
        logging.error("File " + path + " not found.", exc_info=True)
        raise e
    except PermissionError:
        logging.info("File " + path + " used by another process.", exc_info=True)
        success = delete_file(path, attempt+1)
        pass
    return success

def delete_files(input_file_path, n, output_file_path, bunch_size=500, wait_time=0, rt_delay=0):
    """
    Delete files, given a file with complete list of files where each line
    represents a file path, we will randomly delete n files of them.

    :param str input_file_path: path of the input file which contains the list of files.
    :param int n: number of file to delete.
    :return: Returns a file with the list of the deleted files.
    """
    log_filename = 'delete_files.log'
    logging.basicConfig(
        format='%(asctime)s %(levelname)-8s %(message)s',
        datefmt="%Y-%m-%d %H:%M:%S",
        filename=log_filename,
        level=logging.DEBUG,
    )
    data = []
    # Read data into the variable 'data'
    try:
        if input_file_path:
            with open(input_file_path) as f:
                data_ = f.readlines()
            # remove whitespace characters like `\n` at the end of each line
            data = [x.strip() for x in data_]
            f.close()  # close f
    except Exception:
        logging.error('Failed when reading the input file: ', exc_info=True)
    if n is not None:  # Randomly select n paths from data
        to_delete = random.sample(data, n)
    else:  # Delete all files
        to_delete = data
    # Delete the selected files
    deleted_files = []
    count = 0
    for path in to_delete:
        if count >= bunch_size:
              logging.info(f"Bunch end: {count} sleeping {wait_time} seconds")
              time.sleep(wait_time)
              count = 0
        if delete_file(path):
          deleted_files.append(path)
          count += 1
        time.sleep(rt_delay)

    # Write the list of the deleted files into output_file_path
    try:
        with open(output_file_path, 'w') as f:
            for item in deleted_files:
                f.write("%s\n" % item)
        f.close()
    except Exception:
        logging.error('Failed when writing to the output file: ', exc_info=True)


def main():
    parser = argparse.ArgumentParser()

    # Parse arguments
    parser.add_argument("-i", "--input-list", type=str, required=True, dest='input_file',
                        help="File containing the list of files from which we will randomly \
                              select files to be deleted, one per line")
    parser.add_argument("-n", "--n_files", type=int, required=False, dest='n_files',
                        help="Number of files to be randomly selected and deleted")
    parser.add_argument("-o", "--output-list", type=str, required=True, dest='output_file',
                        help="File containing the list of the deleted files, one per line")
    parser.add_argument("-b", '--bunch-size', type=int, default=500,
                        dest="bunch_size", help="File generation bunch size")
    parser.add_argument("-w", '--wait-time', type=int, default=0,
                        dest="wait_time", help="Time interval between bunch generation (to avoid queue overflow)")
    parser.add_argument("-d", "--rt-delay", type=float, default=0,
                        dest="rt_delay", help="Sleep betwen each file generated")
    args = parser.parse_args()

    delete_files(args.input_file, args.n_files, args.output_file, bunch_size=args.bunch_size, wait_time=args.wait_time, rt_delay=args.rt_delay)


if __name__ == '__main__':
    main()
