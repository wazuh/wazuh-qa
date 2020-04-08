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
import datetime
import logging
import argparse
import sys

sys.path.append("/tmp/auxiliary")

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
          help="Sleep time between retries", default="15"
        )

        parser.add_argument("-r", "--retry", type=int, required=False, dest='retry_count',
                            help="reading attempts on stopped alerts. default: 4 attemps",
                            default="3")
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
        parser.add_argument(
            "-an", "--agent_name", type=str, required=True, dest='agent_name',
            help="Agent name", default=None
        )
        parser.add_argument(
            "-os", "--operating_system", type=str, required=True, dest='operating_system',
            help="Operating System Name", default=None
        )
        parser.add_argument(
            "-dt", "--distribution", type=str, required=True, dest='distribution',
            help="Distribution Version", default=None
        )
        parser.add_argument(
            "-md", "--major_distribution", type=str, required=True, dest='major_distribution',
            help="Major Distribution Version", default=None
    )

        args = parser.parse_args()

        log_name = "verify_alerts_json_" + args.scenario_name + "_" \
            + args.event + "_" + args.host + ".log"

        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(message)s",
            datefmt='%Y-%m-%d %H:%M:%S',
            handlers=[
                logging.FileHandler(log_name, mode='a'),
                logging.StreamHandler()
            ]
        )

        import time

        current_retries_count = 0

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
        start = (datetime.datetime.now().replace(microsecond=0))
        elapsed = 0

        passed = True
        logging.info("alerts.json verification started")
        logging.info("Attempt 0/{}".format(args.retry_count))

        while True:
            pruned_alerts_set = alerts_prune(args.log_json_path, args.event)
            sub_paths = paths_list_set - pruned_alerts_set

            if len(sub_paths) == 0:
                logging.info("Verification result is SUCCESS.")
                elapsed = (datetime.datetime.now().replace(microsecond=0)) - start
                return_code = 0
                break

            if current_retries_count > args.retry_count:
                logging.error(
                    "Verification result is FAILED. Number of failed paths: {}/{}".format(len(sub_paths), len(paths_list_set))
                )
                with open(args.output_file, 'w') as f:
                    for item in sub_paths:
                        f.write("%s\n" % item)
                return_code = 3
                passed = False
                break

            if prev_lenght == len(sub_paths):
                logging.warning("Alerts list is NOT growing. Pending alerts to verify are {}".format(len(sub_paths)))
                elapsed = (datetime.datetime.now().replace(microsecond=0)) - start
                current_retries_count += 1

                if current_retries_count <= args.retry_count:
                    logging.info("Attempt {}/{}".format(current_retries_count, args.retry_count))


            time.sleep(args.sleep_time)
            prev_lenght = len(sub_paths)

            logging.info("Elapsed time: %s" % (elapsed))


        expected_alerts_num = len(paths_list_set)
        received_alerts_num = expected_alerts_num - len(sub_paths)

        return return_code
    except Exception:
        logging.critical("An error has ocurred. Exiting")
        raise Exception
    finally:
        logging.info(
            "Number of succeeded files: {}/{}. Elapsed time: {}".format(
                len(paths_list_set) - len(sub_paths), len(paths_list_set), elapsed
            )
        )

        logging.info("Write the result to the global result file")
        generate_result("alerts_json_verification", args.scenario_name, args.agent_name,
                        args.event, passed, expected_alerts_num, received_alerts_num,
                        list(sub_paths), args.result_output_path, args.operating_system,
                        args.distribution, args.major_distribution)

        logging.info("Verification process is finished. Elapsed time: {}".format(elapsed))



if __name__ == "__main__":
    sys.exit(main())
