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
    """ 
    Count lines in file 'filepath' 
    
    :param str filepath: Path of the file to count its lines.

    :return: An integer, the lines number. 
    """
    lines = 0
    with open(filepath) as f:
        for line in f:
            lines += 1
    return lines


def read_database(db_path):
    """
    Read a databas with path 'db_path'.

    :param str db_path: Path of the target database.

    :return: In case if db_path exists it returns the database as a json file.
    """
    if not os.path.exists(db_path):
        return {}
    with open(db_path, 'r') as json_file:
        return json.load(json_file)


def save_database(json_dict, db_path):
    with open(db_path, 'w') as json_file:
        json.dump(json_dict, json_file)


def save_summary(host, action, filepath, json_path):
    """
    Save action summary.

    :param str host: Current host to summarize
    :param str action: Action to summarize
    :param str filepath: File path of action results
    :param str json_path: Path to store json db
    """
    file_number = simplecount(filepath)
    tpl = {action: file_number}
    json_dict = read_database(json_path)
    if host in json_dict:
        json_dict[host].update(tpl)
    else:
        json_dict[host] = tpl
    save_database(json_dict, json_path)


def main():
    parser = argparse.ArgumentParser()

    # Parse arguments
    parser.add_argument("--scenario", type=str, required=True,
                        dest="scenario",
                        help="Scenario to summarize")
    parser.add_argument("--action", type=str, required=True,
                        dest="action",
                        help="Action to summarize")
    parser.add_argument("--action-results", type=str, required=True,
                        dest='results_file',
                        help="File with action execution results")
    args = parser.parse_args()
    basename = os.path.basename(args.results_file)
    host = basename.split(".txt-")[-1]
    scenario_directory = "/opt/fim_test_results/{}".format(args.scenario)
    if not os.path.exists(scenario_directory):
        os.makedirs(scenario_directory, exist_ok=True)
    json_path = "{}/actions_summary.json".format(scenario_directory)
    save_summary(host, args.action, args.results_file, json_path)


if __name__ == '__main__':
    main()
