#!/usr/bin/python3
# Copyright (C) 2015-2020, Wazuh Inc.
# All rights reserved.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

import argparse
from elasticsearch import Elasticsearch
from time import sleep, time
import logging

def read_file(file_path):
    data = []
    # Read data into the variable 'data'
    try:
        if file_path:
            with open(file_path) as f:
                data_ = f.readlines()
            # remove whitespace characters like `\n` at the end of each line
            data = [x.strip() for x in data_]
            f.close()  # close f
    except Exception:
        logging.error('Failed when reading the input file: ', exc_info=True)
    
    return data
def setElasticsearch(ElasticIP):
    """
        Sets the Elasticsearch instance that we want to connect.
        :param str ElasticIP: IP adress of the Elasticsearch node.
        :return: Object of the Elasticsearch class.
    """
    es = Elasticsearch("http://{}:9200".format(ElasticIP))
    return es


def makeQuery(query, Elastic, index_name):
    """
        Make a query to a Elasticsearch instance.
        :param Dict query: Dictionary containing the query we want to make,
        must follow Query DSL.
        :param Elasticsearch Elastic: Elasticsearch class instance we want
        to query.
        :param str index_name: Index  of the Elasticsearch instance we want
        to query.
        :return: Dictionary containing the result of the query.
    """
    result = Elastic.search(index=index_name, body=query)
    return result

def report_failure(start, failure, retry_count, sleep_time):
    """
    Report failures after each retry.

    :param int success: A counter variable used to count the the successful queries.
    :param int failure: A  counter variable used to count the failed queries checks.
    :param int retry_count: The actual retry attempts count.
    :param int sleep_time:  Time to sleep between each retry  of max_retry

    :return int success: success +1
    :return int failure: failure +1
    :return int sleep_time:  Time to sleep between each retry  of max_retry

    """
    elapsed = start - time()

    logging.info("Missing alerts {}.\n".format(failure))
    logging.info("Number of retries {}.\n".format(retry_count))
    logging.info("Elapsed time: ~ {} seconds. \n".format(elapsed))

    retry_count += 1

    sleep(sleep_time)

    return retry_count

def select_scenario(scenarios_dict):
    """
    Select the enabled scenario depending on the scenarios' arguments.

    :param dic scenarios_dict: A dictionary of scenario:argument pairs

    :return str scenario_key[0]: the key of the selected scenario.
    """

    # Get the valid scenario.
    scenario_key = [k for k,v in scenarios_dict.items() if (v != None and v != False)]

    if len(scenario_key) == 1: # if only 1 scenario is enabled, then pass
        return scenario_key[0]
    else: # Check if more than 1 scenario is valid, then fail.
        logging.error("More than 1 scenario is enabled! Please select only 1")

def build_query(query, scenario):
    """
    Build or form the query depending on 'scenario'

    :param dic query: A dictionary which represents the query to run on es.
    :param str scenario: The scenario key to be tested

    :return dic query: query after appending the corresponding term to it.
    """

    scenario_queryterm = {
        'whodata': 'syscheck.path',
        'diff': 'syscheck.path'
    }
    if scenario in scenario_queryterm:
        term = scenario_queryterm[scenario]
        query["query"]["bool"]["filter"].append(
            {"term": {term : ''}}
        )
    else:
        logging.error("The selected scenario is not a valid one")

    return query

def run_line_query(line, query, es, index_name):
    """
    Run query for line on es's index_name

    :param str line: An entry of the original query output which refers to
                     a Syscheck entry.
    :param dic query: A dictionary which represents the query to run on es.
    :param Elasticsearch es: Elasticsearch instance.
    :param str index_name: The name of the index on whcih the search for the files
                           will run.

    :return dic query_result: Represents the query result, which contains the complete
                             list of Syscheck's fields.
    """
    query['query']['bool']['filter'][1]['term']['syscheck.path'] =\
         line.rstrip()
    try:
        query_result = makeQuery(query, es, index_name)
    except Exception as e:
        logging.info("Error when making the  Query: " + str(query))
        raise e

    return query_result

def verify_es_alerts_report_changes(line, query_result, diff_statement, success, failure, failure_list):
    """
    Verify alerts for report_changes query case.

    :param str line: An entry of the original query output which refers to
                     a Syscheck entry.
    :param dic query_result: Represents the query result, which contains the complete
                             list of Syscheck's fields.
    :param diff_statmente: In case of 'report_changes' scenario, diff_statement
                           represents the text added to a file to cause the expected
                           alert.
    :param int success: A counter variable used to count the the successful queries.
    :param int failure: A  counter variable used to count the failed queries checks.
    :param list failure_list: A list to store the failed-query lines, to retry the process
                              again on them.

    :return success: An updated value of the argument success.
    :return failure: An updated value of the argument failure.
    :return failure_list: An updated value of the argument failure_list
    """
    try:
        if ('diff' in query_result['hits']['hits'][0]['_source']['syscheck']) and \
              (diff_statement not in \
               query_result['hits']['hits'][0]['_source']['syscheck']['diff']):
            success += 1
    except IndexError:
        failure_list.append(line)
        failure += 1
    except Exception as e:
        logging.info("Error when filtering audit fields in alert " + line.rstrip())
        raise e

    return success, failure, failure_list

def verify_es_alerts_whodata(line, query_result, success, failure, failure_list):
    """
    Verify alerts for Whodata query case.

    :param str line: An entry of the original query output which refers to
                     a Syscheck entry.
    :param dic query_result: Represents the query result, which contains the complete
                             list of Syscheck's fields.
    :param int success: A counter variable used to count the the successful queries.
    :param int failure: A  counter variable used to count the failed queries checks.
    :param list failure_list: A list to store the failed-query lines, to retry the process
                              again on them.

    :return success: An updated value of the argument success.
    :return failure: An updated value of the argument failure.
    :return failure_list: An updated value of the argument failure_list
    """

    try:
        if (query_result['hits']['hits'][0]['_source']['syscheck']\
                        ['audit']['process']['name'] in query_result):
            success +=1
    except IndexError:
        failure_list.append(line)
        failure += 1
    except Exception as e:
        logging.info("Error when filtering audit fields in alert " + line.rstrip())
        raise e

    return success, failure, failure_list

def verify_es_alerts(files, max_retry, query, es, index_name, start, sleep_time, scenario, scenario_arg):
    """
    Verify Elasticsearch alerts for a specefic scenario.

    :param str files: The path to the file which contain the list of paths
                      of files to be validate their alerts.
    :param int max_retry: Number of retries to repeat as long as there are still paths
                          to be validated.
    :param Elasticsearch es: Elasticsearch class instance.
    :param str index_name: Elasticsearch index name to search in.
    :param time start: time() value at the moment of starting the verification.
    :param int sleep_time: Time to sleep between each retry  of max_retry
    :param bool whodata_query: To check or not a whodata query.
    :param str scenario: The scenario key to be tested
    :param scenario_arg: This variable depends on each scenario.

    :return int success: A counter variable used to count the the successful queries.
    :return int failure: A  counter variable used to count the failed queries checks.
    :return list failure_list: A list to store the failed-query lines, to retry the process
                              again on them.
    """
    retry_count = 0
    logging.info("Elasticsearch alerts verification started")

    query = build_query(query, scenario)

    with open(files, 'r') as file_list:
        while retry_count < max_retry:
            # Initialize auxiliary variables
            success = 0
            failure = 0
            failure_list = []

            for line in file_list: # for each line (path) in file_list
                # Get the corresponding query for line
                query_result = run_line_query(line, query, es, index_name)

                try:
                    if(scenario == "whodata"): # whodata scenarior case
                        success, failure, failure_list = \
                            verify_es_alerts_whodata(line, query_result, success,
                                failure, failure_list)
                    elif(scenario == "diff"): # report_changes scenarior case
                        success, failure, failure_list = \
                            verify_es_alerts_report_changes(line, query_result,
                                scenario_arg, success, failure, failure_list)
                except Exception as e:
                    logging.info("Error when filtering audit fields in alert " + line.rstrip())
                    raise e
            if failure == 0:
                break
            else:
                retry_count = report_failure(start, failure, retry_count, sleep_time)

            return success, failure, failure_list

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler("verify_alerts_elastic.log", mode="a"),
            logging.StreamHandler()
        ]
    )
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-i", "--input-list", type=str, required=True, dest='files',
        help="File containing the list of modified files, one per line"
    )
    parser.add_argument(
        "-e", "--event", type=str, required=True, dest='alert',
        choices=['added', 'modified', 'deleted'],
        help="Type of event that we expect: added, modified, deleted"
    )
    parser.add_argument(
        "-a", "--address", type=str, required=True, dest='ip',
        help="ElasticSearch server IP address"
    )
    parser.add_argument(
        "-o", "--output-list", type=str, required=False,
        dest='output', help="Output path for missing files alerts.",
        default="debug_missing_file_alerts.log"
    )
    parser.add_argument(
        "-r", "--retry", type=int, required=False, dest='max_retry',
        help="reading attempts on stopped alerts. default: 4 attemps",
        default="4"
    )
    parser.add_argument(
        "-s", "--sleep", type=int, required=False, dest='sleep_time',
        help="Sleep time between retries", default="60"
    )
    parser.add_argument(
        "-w", "--whodata", required=False, dest='whodata_query',
        action="store_true", help="Enable whodata queries", default=False
    )
    parser.add_argument("-d", "--diff", type=str, required=False,
        dest='diff_string',help="When syscheck:report_changes enabled, represents the diff text")

    args = parser.parse_args()

    # Global query for Syscheck
    query = {
        "query": {
            "bool": {
                "filter": [
                    {"term": {"syscheck.event": args.alert}}
                ]
            }
        }
    }
    es = setElasticsearch(args.ip)
    index_name = "wazuh-alerts-3.x*"
    start = time()

    # a dictionary for each scenario key name and its argument
    scenario_arg = {
        'whodata': args.whodata_query,
        'diff': args.diff_string
    }
    # select the scenario
    scenario = select_scenario(scenario_arg)

    # alerts verification
    success, failure, failure_list = \
        verify_es_alerts(args.files, args.max_retry, query,
                         es, index_name, start, args.sleep_time,
                         scenario, scenario_arg[scenario])

    elapsed = start - time()
    with open(args.output, 'w+') as output:
        output.writelines(failure_list)

    assert failure == 0, "number of failed files: {}\n \
            Elapsed time: ~ {} seconds.".format(
            success, elapsed
        )

    print(
        "Number of succeded files: {}\n Elapsed time: ~ {} seconds.".format(
            success, elapsed
        )
    )

