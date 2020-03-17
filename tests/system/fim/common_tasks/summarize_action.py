#!/usr/bin/env python3

# Copyright (C) 2015-2020, Wazuh Inc.
# All rights reserved.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

import argparse
import json
import os


def simplecount(filepath):
    """ Count lines in file """
    lines = 0
    with open(filepath) as f:
        for line in f:
            lines += 1
    return lines


def summarize_action(host, action, filepath):
    """
    Create action summary
    :param str host: Testing Host
    :param str action: Action to summarize
    :param str filepath: File path of action results
    """
    file_number = simplecount(filepath)
    return {
        "host": host,
        "action": action,
        "count": file_number
        }


def main():
    parser = argparse.ArgumentParser()

    # Parse arguments
    parser.add_argument("--action", type=str, required=True,
                        dest="action",
                        help="Action to summarize")
    parser.add_argument("--action-results", type=str, required=True,
                        dest='results_file',
                        help="File with action execution results")
    args = parser.parse_args()
    basename = os.path.basename(args.results_file)
    host = basename.split(".txt-")[-1]
    summary = summarize_action(host, args.action, args.results_file)
    with open("test_results/action/{}".format(basename), "w") as sum_file:
        json.dump(summary, sum_file)


if __name__ == '__main__':
    main()
