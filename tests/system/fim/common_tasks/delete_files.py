# Copyright (C) 2015-2020, Wazuh Inc.
# All rights reserved.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

import random
import logging
import os


def delete_files(input_file_path, n, output_file_path):
    """
    Delete files, given a file with complete list of files where each line 
    represents a file path, we will randomly delete n files of them.

    :param str input_file_path: path of the input file which contains the list of files.
    :param int n: number of file to delete.
    :return: Returns a file with the list of the deleted files.
    """
    logger = logging.getLogger()
    data = []
    # Read data into the variable 'data'
    try:
        if input_file_path:
            with open(input_file_path) as f:
                data_ = f.readlines()
            # remove whitespace characters like `\n` at the end of each line
            data = [x.strip() for x in data_]
            f.close() # close f
    except Exception as e:
        logger.error('Failed when reading the input file: ', exc_info=True)


    # Randomly select n paths from data
    to_delete = random.sample(data,n)

    # Delete the selected files
    try:
        for path in to_delete:
            os.remove(path)
    except Exception as e:
        logger.error('Failed when deleting the selected files: ', exc_info=True)

    # Write the list of the deleted files into output_file_path
    try:
        with open(output_file_path, 'w') as f:
            for item in to_delete:
                f.write("%s\n" % item)
        f.close()
    except Exception as e:
        logger.error('Failed when writing to the output file: ', exc_info=True)