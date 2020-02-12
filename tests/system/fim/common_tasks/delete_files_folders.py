# Copyright (C) 2015-2020, Wazuh Inc.
# All rights reserved.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

import json
import random
import logging
import os


def delete_files(input_file_path, n, output_file_path):
    """
    Delete files, given a JSON file with complete list of files, we will randomly delete
    n files of them.
    
    :param str input_file_path: path of the JSON file which contains the list of files.
    :param int n: number of file to delete.
    :return: Returns a JSON file with the list of the deleted files.
    """
    logger = logging.getLogger()

    # Read JSON data into the variable 'data'
    try:
        if input_file_path:
            with open(input_file_path, 'r') as f: # open the file
                data = json.load(f) # put the lines to a variable.
            f.close()
    except Exception as e:
        logger.error('Failed when reading the input file: ', exc_info=True)


    # Randomly select n paths from data
    list_dict_to_delete = random.sample(data['files'],n)
    to_delete = [f['path'] for f in list_dict_to_delete]

    # Delete the selected files
    try:
        os.system("rm -rf "+' '.join(to_delete))
    except Exception as e:
        logger.error('Failed when deleting the selected files: ', exc_info=True)

    # Write the list of the deleted files into output_file_path
    try:
        with open(output_file_path, 'w') as fout:
            json.dump(list_dict_to_delete , fout)
        fout.close()
    except Exception as e:
        logger.error('Failed when writing to the output file: ', exc_info=True)