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

def delete_files(input_file_path, n, output_file_path, bunch_size=100, wait_time=100):
    """
    Delete files, given a file with complete list of files where each line
    represents a file path, we will randomly delete n files of them.

    :param str input_file_path: path of the input file which contains the list of files.
    :param int n: number of file to delete.
    :return: Returns a file with the list of the deleted files.
    """
    log_filename = 'delete_files.log'
    logging.basicConfig(
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
    failed_deletions = []
    count = 0
    for path in to_delete:
        if count >= bunch_size:
              time.sleep(wait_time)
              count = 0
        try:
            os.remove(path)
        except FileNotFoundError as e:
            logging.error("File " + path + " not found.", exc_info=True)
            raise e
        except PermissionError:
            logging.error("File " + path + " used by another process.", exc_info=True)
            failed_deletions.append(path)
            pass
        except Exception:
            raise Exception("Failed when deleting selected files")
        count += 1

    # Retrying deletion on failed paths after sleeping for 3 seconds
    time.sleep(3)
    count = 0
    for path in failed_deletions:
        if count >= bunch_size:
              time.sleep(wait_time)
              count = 0
        try:
            os.remove(path)
        except FileNotFoundError:
            logging.error("File " + path + " not found.(2nd attempt)", exc_info=True)
        except PermissionError:
            logging.error("File " + path + " used by another process.(2nd attempt)", exc_info=True)
            try:
                os.remove(path)
            except Exception:
                logging.error("File " + path + " used by another process.(3rd attempt)", exc_info=True)
                raise Exception
        count += 1

    # Write the list of the deleted files into output_file_path
    try:
        with open(output_file_path, 'w') as f:
            for item in to_delete:
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
    parser.add_argument("-b", '--bunch-size', type=int, default=90,
                        dest="bunch_size", help="File generation bunch size")
    parser.add_argument("-w", '--wait-time', type=int, default=1,
                        dest="wait_time", help="Time interval between bunch generation (to avoid queue overflow)")
    args = parser.parse_args()

    delete_files(args.input_file, args.n_files, args.output_file, bunch_size=args.bunch_size, wait_time=args.wait_time)


if __name__ == '__main__':
    main()
