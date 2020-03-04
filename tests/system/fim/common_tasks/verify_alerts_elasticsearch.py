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
import copy



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

def read_file(file_path):
    """
    read the paths from file_path into a list.

    :param str file_path: The path of the file which contains the paths.
    
    :retrun list data: A list object with the files' paths as elements.
    """

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

def ensure_growing_list(last_num_alerts, query, es, index):
    """
    Ensure the growth of the alerts number in 'index'

    :param int last_num_alerts: The last checked number of alerts
        from the previous run.
    :param dic query: A query to check the number of Syscheck alerts
        with a determined event as filter.
    :param Elasticsearch es: Elasticsearch instance.
    :param str index: The corresponding Elasticsearch index name to
        search in.
    
    :return bool res: True if the list has grwon, False in other case.
    :return int num_alerts: The current number of detected alerts.
    """

    query_result = makeQuery(query, es, index)
    num_alerts = query_result['hits']['total']['value']

    # if alerts list is not growing then return False, else True
    if not (query_result['hits']['total']['value'] > last_num_alerts):
        res = False
    else:
        res = True
    return res, num_alerts

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

    return success, failure

def verify_es_alerts_report_changes(line, query_result, diff_statement, success, failure):
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

    :return success: An updated value of the argument success.
    :return failure: An updated value of the argument failure.
    """

    success_bool = False
    try:
        if query_result['hits']['total']['value'] == 1 and \
           ('diff' in query_result['hits']['hits'][0]['_source']['syscheck']) and \
           (diff_statement in \
                query_result['hits']['hits'][0]['_source']['syscheck']['diff']):
            success += 1
            success_bool = True
        else:
            failure += 1
    except IndexError:
        failure += 1
    except Exception as e:
        logging.info("Error when filtering report_changes fields in alert " + line.rstrip())
        raise e

    return success, success_bool, failure

def verify_es_alerts_whodata(line, query_result, success, failure):
    """
    Verify alerts for Whodata query case.

    :param str line: An entry of the original query output which refers to
                     a Syscheck entry.
    :param dic query_result: Represents the query result, which contains the complete
                             list of Syscheck's fields.
    :param int success: A counter variable used to count the the successful queries.
    :param int failure: A  counter variable used to count the failed queries checks.

    :return success: An updated value of the argument success.
    :return failure: An updated value of the argument failure.
    """
    
    success_bool = False

    try:
        if (query_result['hits']['hits'][0]['_source']['syscheck']\
                        ['audit']['process']['name'] in query_result):
            success +=1
    except IndexError:
        failure += 1
    except Exception as e:
        logging.info("Error when filtering audit fields in alert " + line.rstrip())
        raise e

    return success, success_bool, failure

def verify_es_alerts(files_list, max_retry, query, es, index_name,\
     start, sleep_time, scenario, scenario_arg):
    """
    Verify Elasticsearch alerts for a specefic scenario.

    :param list files_list: A list with the files paths to verify their related alerts.
    :param int max_retry: Number of retries to repeat as long as there are still paths
                          to be validated.
    :param Elasticsearch es: Elasticsearch class instance.
    :param str index_name: Elasticsearch index name to search in.
    :param time start: time() value at the moment of starting the verification.
    :param int sleep_time: Time to sleep between each retry  of max_retry
    :param bool whodata_query: To check or not a whodata query.
    :param str scenario: The scenario key to be tested
    :param scenario_arg: This variable depends on each scenario.

    :return int success: Counter variable used to count the the successful queries.
    :return int failure:  Counter variable used to count the failed queries checks.
    :return list files_list: List of the files' paths with no related alerts detected.
    """

    retry_count = 0
    alerts_num = 0
    success = 0
    failure = 0
    query_scenario = copy.deepcopy(query) #  a copy of query
    query_scenario = build_query(query_scenario, scenario)

    logging.info("Elasticsearch alerts verification started")
    
    while retry_count <= max_retry:
        logging.info("Attempt {}".format(retry_count))

        alerts_growing = False
        alerts_growing, alerts_num = \
            ensure_growing_list(alerts_num, query, es, index_name)
        
        logging.info("alerts_growing state is {} and alerts_num are {}"\
            .format(alerts_growing, alerts_num))

        if retry_count == 0: # if this is the first loop over files_list
            alerts_growing = True

        if alerts_growing:
            for line in files_list[::-1]: # for each line (path) in files_list

                # Get the corresponding query for line
                query_result = run_line_query(line, query_scenario, es, index_name)
                try:
                    if(scenario == "whodata"): # whodata scenarior case
                        success, success_bool, failure = \
                            verify_es_alerts_whodata(line, query_result, success,
                                failure)
                    elif(scenario == "diff"): # report_changes scenarior case
                        success, success_bool, failure = \
                            verify_es_alerts_report_changes(line, query_result,
                                scenario_arg, success, failure)

                    if success_bool: # In case of a success alert verification, then remove line.
                        files_list.remove(line)    
                except Exception as e:
                    logging.info("Error when verifying alerts for " + line.rstrip())
                    raise e
        if failure == 0: # if no failures detected, then break; it's done.
            break
        else: # Retry ...
            retry_count = report_failure(start, failure, retry_count, sleep_time)
    
    return success, failure, files_list

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

    # read the list of paths from a file into a list
    files_list = read_file(args.files)

    # alerts verification
    success, failure, failure_list = \
        verify_es_alerts(files_list, args.max_retry, query,
                         es, index_name, start, args.sleep_time,
                         scenario, scenario_arg[scenario])

    elapsed = start - time()
    with open(args.output, 'w+') as output:
        output.writelines(failure_list)

    assert failure == 0, "number of failed files: {}\n \
            Elapsed time: ~ {} seconds.".format(
            failure, elapsed
        )

    print(
        "Number of succeded files: {}\n Elapsed time: ~ {} seconds.".format(
            success, elapsed
        )
    )

