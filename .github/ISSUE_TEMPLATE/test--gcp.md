| Name | About | Title | Labels | Assigness |
| --- | --- | --- | --- | --- |
| Test: GCP | Test suite for GCP | '' | '' | '' |

# Google Cloud Pub/Sub module

| Version | Revision |
| --- | --- |
| x.y.z | rev |

## Summary

- [ ] GCP001
- [ ] GCP002
- [ ] GCP003
- [ ] GCP004
- [ ] GCP005
- [ ] GCP006
- [ ] GCP007
- [ ] GCP008
- [ ] GCP009


## GCP001

**Short description**

Google Cloud Pub/Sub module folder and its Python scripts should be installed in the wodles path (/var/ossec/wodles by default).

**Category**

GCP

**Description**

The `gcloud` folder will be installed in the Wazuh wodles default folder. Inside it, the Python script will be included. This one accepts options like project ID, subscription name, the credentials file and the maximum number of messages pulled in each iteration.

**Compatible versions**

3.12.0 - Current

**Expected outputs**
```
# ls /var/ossec/wodles/gcloud
```
> gcloud.py  integration.py  __pycache__  tests  tools.py


## GCP002

**Short description**

If the project ID, subscription name or credentials file are not specified in the configuration block, the program won't start.

**Category**

GCP

**Description**

Fields project_id, subscription_name and credentials_file are required to run the Google Cloud Pub/Sub module. Otherwise, the module would not be able to fetch any logs as basic information about the project is missing.

**Compatible versions**

3.12.0 - Current

**Expected outputs**
```
# /var/ossec/bin/wazuh-control restart
```
> 2019/11/26 10:21:05 wazuh-modulesd: ERROR: No value defined for tag 'project_id' in module 'gcp-pubsub'
> 2019/11/26 10:21:05 wazuh-modulesd: ERROR: (1202): Configuration error at '/var/ossec/etc/ossec.conf'.
> wazuh-modulesd: Configuration error. Exiting


## GCP003

**Short description**

The credentials file must be able to be specified as a relative or absolute path and must include the JWT Tokens.

**Category**

GCP

**Description**

Field credentials_file must specify the Google Cloud credentials file with JWTokens. This path should be able to be added as a relative or an absolute path. It will be considered as an absolute path if it starts with a slash '/'. Otherwise, it will be relative to the Wazuh default directory.

**Compatible versions**

3.12.0 - Current

**Expected outputs**

```
2019/11/26 10:51:13 wazuh-modulesd: WARNING: File '/var/ossec/-' from tag 'credentials_file' not found.
2019/11/26 10:51:13 wazuh-modulesd: ERROR: (1202): Configuration error at '/var/ossec/etc/ossec.conf'.
wazuh-modulesd: Configuration error. Exiting
```

## GCP004

**Short description**

The logging option will specify the severity of the events logged by this module.

**Category**

GCP

**Description**

The accepted values for this option are debug, info, warning, error, critical. Depending on which is configured, the wazuh.log file will show messages from this severities. In debug mode, other severity messages and events can be seen at this file.

**Compatible versions**

3.12.0 - Current

**Expected outputs**
Example of critical message shown as DEBUG.

```
2019/11/26 12:02:41 wazuh-modulesd:gcp-pubsub[19341] wm_gcp.c:218 at wm_gcp_run(): DEBUG: OUTPUT: gcloud_wodle - CRITICAL - An exception happened while running the wodle:
Traceback (most recent call last):
  File "/usr/local/lib/python3.6/dist-packages/google/api_core/grpc_helpers.py", line 57, in error_remapped_callable
    return callable_(*args, **kwargs)
  File "/usr/local/lib/python3.6/dist-packages/grpc/_channel.py", line 604, in __call__
    return _end_unary_response_blocking(state, call, False, None)
  File "/usr/local/lib/python3.6/dist-packages/grpc/_channel.py", line 506, in _end_unary_response_blocking
    raise _Rendezvous(state, None, None, deadline)
grpc._channel._Rendezvous: <_Rendezvous of RPC that terminated with:
	status = StatusCode.NOT_FOUND
	details = "Requested project not found or user does not have access to it (project=wazugh-dev-257517). Make sure to specify the unique project identifier and not the Google Cloud Console display name."
	debug_error_string = "{"created":"@1574766161.028456597","description":"Error received from peer ipv4:172.217.17.10:443","file":"src/core/lib/surface/call.cc","file_line":1055,"grpc_message":"Requested project not found or user does not have access to it (project=wazugh-dev-257517). Make sure to specify the unique project identifier and not the Google Cloud Console display name.","grpc_status":5}"
```

## GCP005

**Short description**

Every log retrieved from GCP will be directly forwarded to analysisd, and therefore shown in JSON format in the _archives.log_ file.

**Category**

GCP

**Description**

The Python script will forward every retrieved log to analysisd. They will appear with JSON format in the _archives.log_ file.

**Compatible versions**

3.12.0 - Current

**Expected outputs**

```
2019 Oct 25 18:24:48 manager->Wazuh-GCloud "{\"insertId\":\"u9bpflflzoa46\",\"jsonPayload\":{\"actor\":{\"user\":\"mauro.ezequiel@wazuh.com\"},\"event_subtype\":\"compute.instances.start\",\"event_timestamp_us\":\"1572014759444294\",\"event_type\":\"GCE_API_CALL\",\"ip_address\":\"\",\"operation\":{\"id\":\"1903554319813096520\",\"name\":\"operation-1572014758650-595bd35456130-1711275f-8bce3989\",\"type\":\"operation\",\"zone\":\"europe-west4-a\"},\"request\":{\"body\":\"null\",\"url\":\"https://www.googleapis.com/compute/v1/projects/wazuh-gcp-pubsub-tests/zones/europe-west4-a/instances/backend-server/start?key=AIzaSyDSodt0Zfdm6HAYoNjRFro8odqM5qeppJM\"},\"resource\":{\"id\":\"1201063262651613810\",\"name\":\"backend-server\",\"type\":\"instance\",\"zone\":\"europe-west4-a\"},\"responseCode\":\"ERROR\",\"trace_id\":\"operation-1572014758650-595bd35456130-1711275f-8bce3989\",\"user_agent\":\"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:69.0) Gecko/20100101 Firefox/69.0,gzip(gfe)\",\"version\":\"1.2\"},\"labels\":{\"compute.googleapis.com/resource_id\":\"1201063262651613810\",\"compute.googleapis.com/resource_name\":\"backend-server\",\"compute.googleapis.com/resource_type\":\"instance\",\"compute.googleapis.com/resource_zone\":\"europe-west4-a\"},\"logName\":\"projects/wazuh-gcp-pubsub-tests/logs/compute.googleapis.com%2Factivity_log\",\"receiveTimestamp\":\"2019-10-25T14:45:59.552993938Z\",\"resource\":{\"labels\":{\"instance_id\":\"1201063262651613810\",\"project_id\":\"wazu.h-gcp-pubsub-tests\",\"zone\":\"europe-west4-a\"},\"type\":\"gce_instance\"},\"severity\":\"INFO\",\"timestamp\":\"2019-10-25T14:45:59.444294Z\"}"
```

## GCP006

**Short description**

Logs won't be repeated.

**Category**

GCP

**Description**

The Python script works with a queue. This queue stores every log fetched from Google Cloud Pub/Sub. While they are sent to analysisd, they get removed from this queue, avoiding the possibility of repeating any events.

**Compatible versions**

3.12.0 - Current


## GCP007

**Short description**

If there is no logs to retrieve, the GCP module will show a debug message stating that there are no more events to fetch.

**Category**

GCP

**Description**

When there is no new events shown in the _archives.log_ file, this debug message will be shown.

**Compatible versions**

3.12.0 - Current

**Output**
```
2019/11/26 11:56:17 wazuh-modulesd:gcp-pubsub[17998] wm_gcp.c:218 at wm_gcp_run(): DEBUG: OUTPUT: gcloud_wodle - INFO - Received and acknowledged 0 messages

2019/11/26 11:56:17 wazuh-modulesd:gcp-pubsub[17998] wm_gcp.c:114 at wm_gcp_main(): DEBUG: Fetching logs finished.
```

## GCP008

**Short description**

There are no memory leaks in `wazuh-modulesd`.

**Category**

GCP

**Description**

Tools like Dr. Memory, Valgrind, scan-build, Address Sanitizer or Coverity won't report any memory leaks in this daemon.

**Compatible versions**

3.12.0 - Current


## GCP009

**Short description**

Critical message appears when logs cannot be fetched.

**Category**

GCP

**Description**

If the project ID, subscription name or credentials file are wrong or corrupt, the script won't be able to get logs and report it as a critical message.

**Compatible versions**

3.12.0 - Current

**Output**
```
2019/11/26 12:02:41 wazuh-modulesd:gcp-pubsub[19341] wm_gcp.c:254 at wm_gcp_run(): ERROR: - CRITICAL - An exception happened while running the wodle:
```
