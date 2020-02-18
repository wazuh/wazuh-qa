#!/usr/bin/python3

import argparse
from elasticsearch import Elasticsearch


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
    success = 0
    failure = 0
    failure_list = []

    with open(args.files, 'r') as file_list:
        for line in file_list:
            query['query']['bool']['filter'][0]['term']['syscheck.path'] = \
                line.rstrip()
            query_result = makeQuery(query, es, index_name)
            if query_result['hits']['total']['value'] == 1:
                success += 1
            else:
                failure_list.append(line)
                failure += 1

    with open(args.output, 'w+') as output:
        output.writelines(failure_list)

    assert failure == 0, "number of failed files: {}\n".format(failure)

    print("number of succeded files: {}\n".format(success))
