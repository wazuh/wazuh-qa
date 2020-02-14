import argparse
import json
from elasticsearch import Elasticsearch

def setElasticsearch( ElasticIP):
  es = Elasticsearch("http://{}:9200".format(ElasticIP))
  return es

def makeQuery(query, Elastic, index_name):
  result = Elastic.search(index = index_name, body = query)
  return result

if __name__ == "__main__":

  parser = argparse.ArgumentParser()
  parser.add_argument("-f", "--files", type=str, required=True, dest='files',
    help="File containing the list of modified files, one per line")
  parser.add_argument("-a", "--alert", type=str, required=True, dest='alert',
    choices=['added', 'modified', 'deleted'],
    help="Type of alert that we expect: added, modified, deleted")
  parser.add_argument("-i", "--ip", type=str, required=True, dest='ip',
    help="ElasticSearch server IP")
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

  es  = setElasticsearch(args.ip)
  index_name = "wazuh-alerts-3.x*"
  success = 0
  failure = 0

  with open (args.files, 'r') as file_list:
    for line in file_list:
      query['query']['bool']['filter'][0]['term']['syscheck.path'] = line.rstrip()
      query_result = makeQuery(query, es, index_name)
      if query_result['hits']['total']['value'] == 1:
        success += 1
      else:
        failure += 1

  assert failure == 0, "number of failed files: {}\n".format(failure)

  print("number of succeded files: {}\n".format(success))
