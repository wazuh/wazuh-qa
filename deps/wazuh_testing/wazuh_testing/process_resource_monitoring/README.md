# Monitoring class for process data collection

This package contains two public modules designed for monitoring and tracking purposes:

## Monitor module

The `monitor` module provides a class for monitoring processes and their child processes. Monitoring is conducted concurrently, with a separate thread for each process. The following data is collected for each scan:

   - **Daemon**: daemon name.
   - **Version**: version.
   - **Timestamp**: timestamp of the scan.
   - **PID**: PID of the process.
   - **CPU**(%): CPU percentage of the process. It can exceed 100% if the process uses multiple threads.
   - **VMS**: Virtual Memory Size.
   - **RSS**: Resident Set Size.
   - **USS**: Unique Set Size.
   - **PSS**: Proportional Set Size.
   - **SWAP**: Memory of the process in the swap space.
   - **FD**: File descriptors opened by the process.
   - **Read_Ops**: Read operations.
   - **Write_Ops**: Write operations.
   - **Disk_Read**: Bytes read by the process.
   - **Disk_Written**: Bytes written by the process.

## Disk Usage Tracker module

The `disk_usage_tracker` module provides a class to monitor file and directory disk usage. The following data is collected for each file or directory:

- **File:** Name of the file.
- **Timestamp:** Timestamp of the scan.
- **Path:** Full path of the file.
- **Size:** Size in selected units of the file.
- **Usage:** Percentage of the space the file takes relative to the partition's size.
- **Mod_time:** Last time the file was modified.
- **Acc_time:** Last time the file was accessed.
- **Creat_time:** Creation time (Windows) or metadata change time (Unix).

The package also provides the script `wazuh-metrics`, designed to interact with these modules. [More information](#script)
 
### Process reference

#### Wazuh manager

| Process | Argument |
| ------- | -------- |
| wazuh-agentlessd | agentlessd |
| wazuh-analysisd | analysisd |
| wazuh_apid.py | apid |
| wazuh-authd | authd |
| wazuh_clusterd.py | clusterd |
| wazuh-csyslogd | csyslogd |
| wazuh-db | db |
| wazuh-dbd | dbd |
| wazuh-execd | execd |
| wazuh-integratord | integratord |
| wazuh-logcollector | logcollector |
| wazuh-maild | maild |
| wazuh-modulesd | modulesd |
| wazuh-monitord | monitord |
| wazuh-remoted | remoted |
| wazuh-syscheckd | syscheckd |

> Note:  
> `wazuh_apid.py` and `wazuh_clusterd.py` are scripts run by the Python interpreter, not processes themselves.

#### Wazuh agent

| Process | Argument |
| ------- | -------- |
| wazuh-agentd | agentd |
| wazuh-execd | execd |
| wazuh-logcollector | logcollector |
| wazuh-modulesd | modulesd |
| wazuh-syscheckd | syscheckd |


## Directory structure

```shell script
process_resource_monitoring/
├── pyproject.toml
├── README.md
└── src
    ├── process_resource_monitoring
    │   ├── disk_usage_tracker.py
    │   ├── __init__.py
    │   ├── _logger.py
    │   └── monitor.py
    └── wazuh_metrics.py
```


## Prerequisites

- Wazuh component(s) 4.9.0 (or greater)
- Python 3.7 (or greater)
- Python-pip (pip)


## Package installation

To use the monitoring class in any other Python scripts it is highly recommended to install the package. This can be achieved by following these steps:

```shell script
# Create a virtual environment
python3 -m venv virtualenv
source virtualenv/bin/activate

# Install the package using pip
python3 -m pip install .

# Verify the correct installation
python3 -m pip list | grep process_resource_monitoring
```

> Note:  
> The use of a virtual environment is optional, but quite recommended to avoid polluting the global workspace.


## Script

This script takes as positional arguments the names of the processes to be monitored.

```shell script
wazuh-metrics <process_name> [<process_name>,...]
```

### Parameters


| Parameter | Description | Type | Default |
| --------- | ----------- | ---- | ------- |
| `<process_name_list>` | `Name of process/processes to monitor separated by whitespace.` | `str` | Required |
| `--disk` | `Paths of the files/dirs to monitor their disk usage.` | `str` | `None` |
| `-s`, `--sleep` | `Time in seconds between each entry.` | `float` | `1.0` |
| `-u`, `--units` | `Unit for the process bytes-related values.` | `str` | `KB` |
| `--disk-unit` | `Unit for the disk usage related values.` | `str` | `GB` |
| `-v`, `--version` | `Version of the binaries.` | `str` | `None` |
| `-d`, `--debug` | `Enable debug level logging.` | `store_true` | `False` |
| `-H`, `--healthcheck-time` | `Time in seconds between each health check.` | `int` | `10` |
| `-r`, `--retries` | `Number of reconnection retries before aborting the monitoring process.` | `int` | `10` |
| `--store-process` | `Path to store the CSVs with the process resource usage data.` | `str` | `` |
| `--store-disk` | `Path to store the CSVs with the disk usage data.` | `str` | `` |


### Usage examples

```shell script
# Min arguments: names of the processes to monitor (Process reference section)
wazuh-metrics authd analysisd

# Monitor api, cluster, mail and logcollector. Frequency 5s. Units to store the main memory values MB
wazuh-metrics apid clusterd maild logcollector -s 5 -u MB

# Monitor api and logcollector. Track usage of the file `/var/ossec/logs/archives/archives.json`
wazuh-metrics apid logcollector --disk /var/ossec/logs/archives/archives.json
```
