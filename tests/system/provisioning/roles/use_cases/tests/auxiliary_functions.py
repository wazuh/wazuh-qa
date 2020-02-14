import json
import testinfra

elasticsearch_index = "/wazuh-alerts-3.x-*"
elasticsearch_search_sufix = "/_search"
curl_timeout = 15

def api_call_wazuh(host,query,address,api_protocol,api_user,api_pass,api_port):
    if (api_pass != ""):
        response = host.run("curl --max-time " + str(curl_timeout) + " -k -u " + api_user + ":" + api_pass + " " + api_protocol + "://" + address + ":" + api_port + query )
        print (response)
    else:
        response = host.run("curl --max-time " + str(curl_timeout) + " " + api_protocol + "://" + address + ":" + api_port + query )
    return response

def api_call_elasticsearch(host,query,address,api_protocol,api_user,api_pass,api_port):

    if (query == ""):   # Calling ES API without query
        if (api_pass != "" and api_pass != ""): # If credentials provided
            response = host.run("curl --max-time " + str(curl_timeout)
                                + " -k -u "     + api_user + ":" + api_pass + " "
                                + api_protocol + "://" + address + ":" + api_port
                                )
        else:
            response = host.run("curl --max-time " + str(curl_timeout) + " " + api_protocol + "://" + address + ":" + api_port)

    elif (query != ""): # Executing query search
        if (api_pass != "" and api_pass != ""):
            response = host.run("curl -H \'Content-Type: application/json\'"
                                + " --max-time " + str(curl_timeout)
                                + " -k -u "     + api_user + ":" + api_pass
                                + " -d '"        + json.dumps(query) + "' "
                                + api_protocol + "://" + address + ":" + api_port
                                + elasticsearch_index + elasticsearch_search_sufix
                                )
        else:
            response = host.run("curl --max-time " + str(curl_timeout) + " " + api_protocol + "://" + address + ":" + api_port)
    
    else:
        response = "Error. Unable to classify Elasticsearch API call"
        
    return response
