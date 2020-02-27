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
        "-w", "--whodata", type=bool, required=False, dest='whodata_query',
        help="Enable whodata queries", default="False"
    )
    args = parser.parse_args()

    query = {
        "query": {
            "bool": {
                "filter": [
                    {"term": {"syscheck.path": ""}},
                    {"term": {"syscheck.event": args.alert}}
                ]
            }
        }
    }

    es = setElasticsearch(args.ip)
    index_name = "wazuh-alerts-3.x*"
    retry_count = 0
    logging.info("Elasticsearch alerts verification started")
    start = time()
    with open(args.files, 'r') as file_list:
        while retry_count < args.max_retry:
            success = 0
            failure = 0
            failure_list = []
            for line in file_list:
                query['query']['bool']['filter'][0]['term']['syscheck.path'] =\
                    line.rstrip()
                try:
                    query_result = makeQuery(query, es, index_name)
                    print(query_result)
                except Exception as e:
                    logging.info("Error when making the  Query of " + str(args.whodata_query))
                    raise e

                if (args.whodata_query):
                    try:
                        if (query_result['hits']['hits'][0]['_source']['syscheck']['audit']['process']['name'] in query_result):
                            success +=1
                    except IndexError:
                        failure_list.append(line)
                        failure += 1
                    except Exception as e:
                        logging.info("Error when filtering audit fields in alert " + line.rstrip())
                        raise e
                else:
                    try:
                        if query_result['hits']['total']['value'] == 1:
                            success += 1
                    except IndexError:
                        failure_list.append(line)
                        failure += 1
                    except Exception as e:
                        logging.info("Error when filtering syscheck alerts hits of " + line.rstrip())
                        raise e
            if failure == 0:
                break
            else:
                elapsed = start - time()
                logging.info("Missing alerts {}.\n".format(failure))
                logging.info("Number of retries {}.\n".format(retry_count))
                logging.info("Elapsed time: ~ {} seconds. \n".format(elapsed))
                retry_count += 1
                sleep(args.sleep_time)

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
