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
import traceback

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
    with open(path,errors='replace') as json_file:
        for line in json_file:
            try:
                data = json.loads(line)
                if data.get('syscheck') and data['syscheck']['event'] == target_event:
                    alerts_list.append(data)
            except ValueError:
                continue
    return set([alerts['syscheck']['path'] for alerts in alerts_list])


def main():

    try:

        import argparse

        parser = argparse.ArgumentParser(description='Compares paths list and alerts.json paths')

        parser.add_argument("-i", "--input-list", type=str, required=True, dest='input_file',
                            help="File containing the list of modified files, one per line")

        parser.add_argument("-e", "--event", type=str, required=True, dest='event',
                            choices=['added', 'modified', 'deleted'],
                            help="Type of alert's event that we expect: added, modified, deleted")

        parser.add_argument("-l", "--log_json", type=str, required=False, dest='log_json_path',
                            help="alerts.json path. default value '/var/ossec/logs/alerts/alerts.json'",
                            default="/var/ossec/logs/alerts/alerts.json")

        parser.add_argument("-o", "--output-list", type=str, required=False, dest='output_file',
                            help="Output path for missing files alerts.",
                            default="debug_missing_file_alerts.log")

        parser.add_argument("-t", "--timeout", type=int, required=False, dest='time_gap',
                            help="time gap between alerts.json alerts acquisitions. default: 30s",
                            default="30")

        parser.add_argument("-r", "--retry", type=int, required=False, dest='retry_count',
                            help="reading attempts on stopped alerts. default: 4 attemps",
                            default="4")
        args = parser.parse_args()

        import time

        stuck_alerts = 0

        paths_list_set = paths_acquisition(args.input_file)
        pruned_alerts_set = alerts_prune(args.log_json_path, args.event)
        sub_paths = paths_list_set - pruned_alerts_set
        prev_lenght = len(sub_paths)
        start = time.time()

        print("alerts.json verification started")
        while True:
            pruned_alerts_set = alerts_prune(args.log_json_path, args.event)
            sub_paths = paths_list_set - pruned_alerts_set

            if len(sub_paths) == 0:
                print("Verify alerts test - OK.")
                return 0
            if stuck_alerts > args.retry_count:
                print("Verify alerts test - NOT OK. %s alerts are missing.\n" % len(sub_paths))
                with open(args.output_file, 'w') as f:
                    for item in sub_paths:
                        f.write("%s\n" % item)
                    f.write("%s missing alerts.\n" % len(sub_paths))
                return 1

            if prev_lenght == len(sub_paths):
                print("Filelist related alerts aren't growing (%s) ..." % stuck_alerts)
                stuck_alerts += 1
            else:
                stuck_alerts = 0

            time.sleep(args.time_gap)
            prev_lenght = len(sub_paths)
            elapsed = time.time() - start
            print("Elapsed time: ~ %s seconds \n" % int(elapsed))

    except Exception:
        traceback.print_exc()


if __name__ == "__main__":
    main()
