# Data Visualization Module

This module contains a basic application developed with Dash and Plotly that allows to visualize different data from CSV files in a simple, representative and easily interpretable way. It allows you to dynamically choose which type of data to display and to which file it belongs, making data comparison much easier.

## Initial setup

To run these tests, we need to install the package. So we can follow these steps:

1. Move to the `wazuh_testing/data_visualization_module` directory.
2. Create and activate the Python environment.

```shell script
python3 -m venv env
source env/bin/activate
```

3. Install the package

```shell script
python3 -m pip install .
```

## Run module

To run this module, we will need to use the following command:

```shell script
python3 app.py --config items_config.yml
```

When the module is running, we must access `http://127.0.0.1:8050/` in a browser to view the data.

### Parameters

- `--config`: YAML file containing the component and the processes to visualize. It also includes those CSV columns that are not required for visualization and should be omitted.

An example of the structure of this file could be the following:

```shell script
Component:
  - "manager"

Processes:
  Daemon:
    - "wazuh-clusterd"
    - "wazuh-integratord"
    - "wazuh-execd"
    - "wazuh-logcollector"
    - "wazuh-analysisd"
    - "wazuh-db"
    - "wazuh-maild"
    - "wazuh-authd"
    - "wazuh-syscheckd"
    - "wazuh-monitord"
    - "wazuh-modulesd"
    - "wazuh-remoted"

Columns_to_avoid:
  - "Daemon"
  - "Version"
  - "Timestamp"
  - "Commit"
```

The `Component` value can take one of these: [`manager`, `indexer`, `agent` or `dashboard`].

This file indicates that we want to visualize the manager data and, in addition, we want to visualize the daemon processes that are listed. In addition, it is indicated that in the CSV file there are some columns that are not necessary for the visualization, such as version, timestamp or commit, so they can be omitted. This only indicates to the application the columns that are not necessary to render. The rest of the columns are the ones that will be rendered and, typically, will be the metrics that contain the values taken during the tests. So, to resume, in the `Columns_to_avoid` section we should include those informative columns of the CSV, whose data type is usually string.

Another example of a configuration file:

```shell script
Component:
  - "dashboard"

Processes:
  Item:
    - "wazuh-dashboard"

Columns_to_avoid:
  - "Daemon"
  - "Version"
  - "Timestamp"
  - "Commit"
```

This means that the visualization is not only valid for Wazuh daemons, but also for other types of processes.

### CSV format

The CSV file name must match the value in the `Version` column. This is to improve the efficiency of database queries. For example: `4.8.0-beta4.csv`. In addition to the `Version` column, it should contain another column named `Commit`, indicating the commit in which the file was obtained (e.g. nightly, weekly, pre-release, etc.), and a column with the process to be displayed, which can be the wazuh daemons, the wazuh-dashboard itself, etc. The name of this same column must match the name specified in the YAML file. The rest of the columns may be informative columns, of type string, which must be included in `Columns_to_avoid` in the YAML file, and data columns containing the metrics taken.

Considering the two examples of YAML files above, the CSV files could be respectively:

```shell script
Version,Commit,Timestamp,Daemon,CPU(%),RSS(KB),VMS(KB),FD,Read_Ops,Write_Ops,Disk_Read(B),Disk_Written(B),Disk(%),USS(KB),PSS(KB),SWAP(KB)
4.8.1,pre-release,2024-07-05 21:12:27,wazuh-syscheckd,0.0,8188.0,76972.0,7,20,21,0,49152,0.00019935213463462376,2720.0,3819.0,0.0
4.8.1,pre-release,2024-07-05 21:12:27,wazuh-analysisd,0.0,34944.0,1159264.0,24,1766,37,0,57344,0.00023257749040706108,32412.0,32720.0,0.0
4.8.1,pre-release,2024-07-05 21:12:27,wazuh-maild,0.0,0.0,0.0,0,0,0,0,0,0,0.0,0.0,0.0
4.8.1,pre-release,2024-07-05 21:12:27,wazuh-execd,0.0,3772.0,46484.0,5,11,3,0,8192,3.3225355772437296e-05,1740.0,1831.0,0.0
4.8.1,pre-release,2024-07-05 21:12:27,wazuh-modulesd,0.0,112060.0,584528.0,132,28063,41097,90960896,300437504,1.5874452012649805,100996.0,104033.0,0.0
4.8.1,pre-release,2024-07-05 21:12:27,wazuh-clusterd,0.0,0.0,0.0,0,0,0,0,0,0,0.0,0.0,0.0
4.8.1,pre-release,2024-07-05 21:12:27,wazuh-db,0.0,18448.0,959756.0,40,6738,931,5345280,2187264,0.03055071463275609,10996.0,12981.0,0.0
4.8.1,pre-release,2024-07-05 21:12:27,wazuh-remoted,0.0,20204.0,1246528.0,39,5166,2097,0,57344,0.00023257749040706108,13092.0,14940.0,0.0
4.8.1,pre-release,2024-07-05 21:12:27,wazuh-integratord,0.0,0.0,0.0,0,0,0,0,0,0,0.0,0.0,0.0
4.8.1,pre-release,2024-07-05 21:12:27,wazuh-monitord,0.0,4080.0,55424.0,8,13,2,0,4096,1.6612677886218648e-05,1960.0,2056.0,0.0
4.8.1,pre-release,2024-07-05 21:12:27,wazuh-authd,0.0,7900.0,136788.0,7,16,4,8192,4096,4.983803365865594e-05,2096.0,3033.0,0.0
```

```shell script
Version,Commit,Timestamp,Item,Seconds
4.8.0,pre-release,2024-08-06 19:02:44,wazuh-dashboard,60
4.8.0,pre-release,2024-08-06 19:02:54,wazuh-dashboard,70
4.8.0,pre-release,2024-08-06 19:03:04,wazuh-dashboard,80
4.8.0,pre-release,2024-08-06 19:03:14,wazuh-dashboard,90
4.8.0,pre-release,2024-08-06 19:03:24,wazuh-dashboard,100
4.8.0,pre-release,2024-08-06 19:03:34,wazuh-dashboard,1100
```

### Database

The data to be displayed must be inserted into a local database which is located in the `data/data.db` directory. For this, there is a script (in the `scripts` directory) that inserts the data from the CSV files of a given directory into the database.

The database has a column named `component` in order to differentiate the files of each Wazuh component. Therefore this script must be executed like this:

```shell script
python3 db_data_insertion.py <directory> <component>
```

Where `<directory>` refers to the path where the CSV files are stored and `<component>` refers to the component to which the CSV files belong. For this, it would be convenient to have a separate directory for each component. The `<component>` argument can take one of these values: [`manager`, `indexer`, `agent` or `dashboard`].

For example:

```shell script
python3 db_data_insertion.py ./data/manager_csv_files manager
```
