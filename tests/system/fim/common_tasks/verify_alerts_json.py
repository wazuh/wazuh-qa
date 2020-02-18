#!/usr/bin/python3

# Copyright (C) 2015-2020, Wazuh Inc.
# All rights reserved.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

import sys
import json

if sys.version_info.major < 3:
    print('ERROR: Python 2 is not supported.')
    sys.exit(1)


def paths_acquisition(filenames_list_path):
    """
        Turn path lists file into a set.
        :param str filenames_list_path: path to filenames list
        :return: Returns a set containing the generated files path
    """
    filenames_list = []
    with open(filenames_list_path) as lines:
        filenames_list = lines.readlines()
    return set([i[:-1] for i in filenames_list])


def alerts_prune(path, target_event):
    """
        Prunes desired syscheck events from the alert.json file.
        Extracts all events path to a set.
        :param str path: path to alerts.json file
        :param str target_event: target event kind (deleted|added|modified)
        :return: Returns a set containing the alerts files path
    """
    alerts_list = []
    with open(path) as json_file:
        for line in json_file:
            data = json.loads(line)
            if data.get('syscheck') and data['syscheck']['event'] == target_event:
                alerts_list.append(data)
    return set([alerts['syscheck']['path'] for alerts in alerts_list])


def main():

    import argparse
    parser = argparse.ArgumentParser(description='Compares paths list and alerts.json paths')

    parser.add_argument("-i", "--input_path", type=str, required=True, dest='files',
                        help="File containing the list of modified files, one per line")

    parser.add_argument("-e", "--event", type=str, required=True, dest='event',
                        choices=['added', 'modified', 'deleted'],
                        help="Type of alert's event that we expect: added, modified, deleted")

    parser.add_argument("-l", "--log_json", type=str, required=False, dest='log_json_path',
                        help="alerts.json path. default value '/var/ossec/logs/alerts/alerts.json'",
                        default="/var/ossec/logs/alerts/alerts.json")

    parser.add_argument("-o", "--output-list", type=str, required=False, dest='output',
                        help="Output path for missing files alerts.",
                        default="debug_missing_file_alerts.log")
    args = parser.parse_args()
    paths_list_set = paths_acquisition(args.files)
    pruned_alerts_set = alerts_prune(args.log_json_path, args.event)
    sub_paths = paths_list_set - pruned_alerts_set
    if len(sub_paths) == 0:
        print("Test passed")
        return 0
    else:
        print("Test failed. %s alerts are missing\n" % len(sub_paths))
        with open(args.output, 'w') as f:
            for item in sub_paths:
                f.write("%s\n" % item)
            f.write("%s alerts for the paths above are missing on alerts.json\n" % len(sub_paths))
        return 1


if __name__ == "__main__":
    main()
