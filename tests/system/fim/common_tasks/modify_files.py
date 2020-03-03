#!/usr/bin/env python3

# Copyright (C) 2015-2020, Wazuh Inc.
# All rights reserved.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

import os
import sys
import random
import platform
import argparse
import time
import logging
if platform.system() == 'Linux':
    import pwd
    import grp


if sys.version_info.major < 3:
    print('ERROR: Python 2 is not supported.')
    sys.exit(1)


def random_mode():
    """
    Returns a random file permission

    File permission in unix use octal format, but os.chmod expects a decimal.
    Numbers 0 and 511 are the min and max (decimal) numbers accepted,
    being 0 equivalent to 000 and 511 equivalent to 777 in octal.
    """
    return random.randint(0, 511)


def modify_file(filepath, owner, group, mode):
    """
        Modify a file owner, group and permissions.
        :param str filepath: Full path of the file
        :param str owner: File owner
        :param str group: File group
        :param int mode: File permissions in decimal format
        :return: Returns a dictionary with the change metadata
    """
    uid = pwd.getpwnam(owner).pw_uid
    gid = grp.getgrnam(group).gr_gid
    os.chown(filepath, uid, gid)
    os.chmod(filepath, mode)
    return {
        'path': filepath,
        'uid': uid,
        'gid': gid,
        'mode': oct(mode).split('o')[1].zfill(3)  # convert to octal string
    }


def modify_file_content(filepath):
    """
        Modify file content by adding a random number of bytes

        :param str filepath: The path of the file to modify
    """
    content = 'qazxswedcvbnmklpoiuytggdfert' * random.randint(1, 10)
    content += str(random.random())
    if not os.path.exists(filepath):
        raise FileNotFoundError
    with open(filepath, 'ab') as f:
        f.write(bytes(content, 'utf8'))

def modify_file_text_content(filepath, sentence):
    """
    Modify file content by adding sentence at the end of filepath
    in a new line.

    :param str filepath: The path of the file to modify
    :param str sentence: A setnence of 1 or more words.
    """
    with open(filepath, 'r+') as file:
        content = file.read()
        file.seek(0, 0)
        file.write(sentence.rstrip('\r\n') + '\n' + content)

def log_modified_files(files_path, logfile):
    """
    Creates a file that summarizes all the modified files

    :param dict files_path: Contains the list of modified files
    :param str logfile: File to write the list of paths
    """
    if os.path.exists(logfile):
        os.remove(logfile)
    with open(logfile, 'w') as f:
        for path in files_path:
            f.write(path + '\n')


def main():
    log_filename = 'modify_files.log'
    logging.basicConfig(
        format='%(asctime)s %(levelname)-8s %(message)s',
        datefmt="%Y-%m-%d %H:%M:%S",
        filename=log_filename,
        level=logging.DEBUG,
    )
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input-list", type=str,
                        required=True, dest='input_file',
                        help="File containing the list of files to modify")
    parser.add_argument("-o", "--output-list", type=str,
                        required=True, dest='output_file',
                        help="File containing the list of modified files")
    parser.add_argument("-t", '--text-mode', default=False, action="store_true",
                        dest="text_mode", help="Modify text files instead of binary"
                             " (default is False)")
    parser.add_argument("-b", '--bunch-size', type=int, default=500,
                        dest="bunch_size", help="File generation bunch size")
    parser.add_argument("-w", '--wait-time', type=int, default=0,
                        dest="wait_time", help="Time interval between bunch generation (to avoid queue overflow)")
    parser.add_argument("-d", "--rt-delay", type=float, default=0,
                        dest="rt_delay", help="Sleep betwen each file generated")
    args = parser.parse_args()

    input_file = args.input_file
    output_file = args.output_file
    text_mode = args.text_mode

    changed_files = []
    sentence = "Hello World"

    with open(input_file) as flist:
        count = 0
        nbunch = 0
        for path in flist:
            time.sleep(args.rt_delay)
            count += 1
            if count >= args.bunch_size:
              logging.info(f"Bunch end: {nbunch} sleeping {args.wait_time} seconds")
              time.sleep(args.wait_time)
              count = 0
              nbunch += 1
            try:
                if text_mode: # if text_mode, then add 'setence' at the end of 'path'
                    modify_file_text_content(path[:-1], sentence)
                else:
                    modify_file_content(path[:-1])
                changed_files.append(path[:-1])
            except PermissionError:
                logging.error("Not enough permissions to modify: {}".format(path[:-1]))
                continue
            except FileNotFoundError:
                logging.error("File not found: {}".format(path[:-1]))
                continue
            except Exception:
                logging.error("Unexpected error: ", exc_info=True)
                continue
    log_modified_files(changed_files, output_file)


if __name__ == "__main__":
    main()
