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

import logging
import argparse

import sys
sys.path.append('/home/vagrant')

from generate_results import generate_result


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


def alerts_prune(path, target_event, diff_statement=None):
    """
        Prunes desired syscheck events from the alert.json file.
        Extracts all events path to a set.
        :param str path: path to alerts.json file
        :param str target_event: target event kind (deleted|added|modified)
        :return: Returns a set containing the alerts files path
    """
    alerts_list = []
    add_path = True
    with open(path,errors='replace') as json_file:
        for line in json_file:
            try:
                data = json.loads(line)
                if data.get('syscheck') and \
                   data['syscheck']['event'] == target_event:
                    if (diff_statement is not None) and \
                       ('diff' in data['syscheck']) and \
                       (diff_statement not in data['syscheck']['diff']):
                            add_path = False
                    if add_path:
                        alerts_list.append(data)
                    add_path = True   
            except ValueError:
                continue
    return set([alerts['syscheck']['path'] for alerts in alerts_list])


def alerts_prune_whodata(path, target_event):
    """
        Prunes desired whodata events from the alert.json file.
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
                if (data['syscheck']['audit'] is not None and data['syscheck']['event'] == target_event):
                    if (data['syscheck']['audit']['user']['id'] != ""
                        and data['syscheck']['audit']['user']['name'] != ""
                        and data['syscheck']['audit']['process']['id'] != ""
                        and data['syscheck']['audit']['process']['name'] != ""
                        ):
                        alerts_list.append(data)
            except ValueError:
                continue
            except KeyError:
                continue
    return set([alerts['syscheck']['path'] for alerts in alerts_list])


def alerts_prune_tag(path, target_event, tags):
    """
        Prunes desired syscheck events from the alert.json file.
        Extracts all events path to a set.
        :param str path: path to alerts.json file
        :param str target_event: target event kind (deleted|added|modified)
        :return: Returns a set containing the alerts files path
    """
    alerts_list = []
    with open(path, 'r', errors='replace') as json_file:
        for line in json_file:
            try:
                data = json.loads(line)
                if data.get('syscheck') \
                    and data['syscheck']['event'] == target_event \
                        and 'tags' in data['syscheck']:
                    if data['syscheck']['tags'] == tags:
                        alerts_list.append(data)

            except ValueError:
                continue
    return set([alerts['syscheck']['path'] for alerts in alerts_list])


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt='%Y-%m-%d %H:%M:%S',
        handlers=[
            logging.FileHandler("verify_alerts_json.log", mode='a'),
            logging.StreamHandler()
        ]
    )
    try:
        parser = argparse.ArgumentParser(description='Compares paths list and alerts.json paths')

        parser.add_argument("-i", "--input-list", type=str, required=True, dest='input_file',
                            help="File containing the list of modified files, one per line")

        parser.add_argument("-e", "--event", type=str, required=True, dest='event',
                            choices=['added', 'modified', 'deleted'],
                            help="Type of alert's event that we expect: added, modified, deleted")

        parser.add_argument("-l", "--log_json", type=str, required=False, dest='log_json_path',
                            help="alerts.json path. default value "
                            "'/var/ossec/logs/alerts/alerts.json'",
                            default="/var/ossec/logs/alerts/alerts.json")

        parser.add_argument("-o", "--output-list", type=str, required=False, dest='output_file',
                            help="Output path for missing files alerts.",
                            default="debug_missing_file_alerts.log")

        parser.add_argument("-s", "--sleep", type=int, required=False, dest='sleep_time',
          help="Sleep time between retries", default="60"
        )

        parser.add_argument("-r", "--retry", type=int, required=False, dest='retry_count',
                            help="reading attempts on stopped alerts. default: 4 attemps",
                            default="4")
        parser.add_argument("-d", "--diff", type=str, required=False, dest='diff_string',
                            help="When syscheck:report_changes enabled, represents the diff text")
        parser.add_argument("-w", "--whodata", required=False, dest='whodata_check',
                            action="store_true", help="Enable Whodata alert's parsing.",
                            default=False)
        parser.add_argument(
            "-tg", "--tag", type=str, required=False, dest='tag_query',
            nargs='+', help="Enable tag queries for the indicated tags",
            default=None
        )
        parser.add_argument(
            "-sn", "--scenario_name", type=str, required=True, dest='scenario_name',
            help="Scenario complete name", default=None
        )
        parser.add_argument(
            "-ho", "--host", type=str, required=True, dest='host',
            help="Agent host IP", default=None
        )
        parser.add_argument(
            "-ro", "--result_output", type=str, required=True, dest='result_output_path',
            help="Result output file path", default=None
        )
        args = parser.parse_args()

        import time

        stuck_alerts = 0

        paths_list_set = paths_acquisition(args.input_file)
        pruned_alerts_set = alerts_prune(args.log_json_path, args.event, args.diff_string)

        if (args.whodata_check is not None and args.whodata_check):
            logging.info(
                "Pruning whodata alerts."
            )
            pruned_alerts_set = alerts_prune_whodata(args.log_json_path, args.event)
        elif args.tag_query is not None:
            logging.info(
                "Pruning tag alerts."
            )
            pruned_alerts_set = alerts_prune_tag(
                 args.log_json_path, args.event, args.tag_query
            )
        if not args.whodata_check and args.tag_query is None:
            logging.info(
                "Pruning alerts."
            )
            pruned_alerts_set = alerts_prune(args.log_json_path, args.event)

        sub_paths = paths_list_set - pruned_alerts_set
        prev_lenght = len(sub_paths)
        start = time.time()

        logging.info("alerts.json verification started")

        while True:
            pruned_alerts_set = alerts_prune(args.log_json_path, args.event)
            sub_paths = paths_list_set - pruned_alerts_set

            if len(sub_paths) == 0:
                logging.info("Verify alerts test - OK.")
                returb_code = 0
                break

            if stuck_alerts > args.retry_count:
                logging.error(
                    "Verify alerts test - NOT OK. %s alerts are missing.\n" % len(sub_paths)
                )
                with open(args.output_file, 'w') as f:
                    for item in sub_paths:
                        f.write("%s\n" % item)
                logging.warning("%s missing alerts.\n" % len(sub_paths))
                returb_code = 1
                break

            if prev_lenght == len(sub_paths):
                logging.warning("Filelist related alerts aren't growing (%s) ..." % stuck_alerts)
                stuck_alerts += 1
            else:
                stuck_alerts = 0

            time.sleep(args.sleep_time)
            prev_lenght = len(sub_paths)
            elapsed = time.time() - start
            logging.info("Elapsed time: ~ %s seconds \n" % int(elapsed))
        
    
        passed = stuck_alerts == 0
        expected_alerts_num = len(paths_list_set)
        received_alerts_num = expected_alerts_num - len(sub_paths)

        logging.info("Write the result to the global result file")
        generate_result(args.scenario_name, args.host, args.event, passed, expected_alerts_num, 
                        received_alerts_num, list(sub_paths), args.result_output_path)

        return returb_code
    except Exception:
        logging.critical("An error has ocurred. Exiting")
        raise Exception


if __name__ == "__main__":
    sys.exit(main())
