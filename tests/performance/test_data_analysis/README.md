# Statistical Data Analyzer Module

This module contains a basic test that allows you to perform statistical analysis and calculations on two data sets and to make comparisons between them. This allows to detect significant differences between the two sets automatically.

This test uses t-Student, Levene and ANOVA tests to detect possible significant differences in the metrics of the data sets. If such differences exist, comparisons are made between the main statistics with respect to a threshold value which, if exceeded, is marked as an error and reported conveniently.

The analysis is performed specifically for the processes, metrics and statistics that are specified in a YML file, in which the threshold value for each statistic will also be indicated.

## Initial setup

To run these tests, we need to install the package. So we can follow these steps:

1. Move to the `performance/test_data_analysis` directory.
2. Create and activate the Python environment.

```shell script
python3 -m venv env
source env/bin/activate
```

3. Install the packages

```shell script
python3 -m pip install .
```

## Pytest

To run the tests, we will need to use the following command:

```shell script
python3 -m pytest test_data_analyzer_module.py --baseline <baseline_csv_file> --datasource <data_csv_file> --items_yaml <yml_file> --html=<html_file> <--optional_parameters>
```

### Parameters

| Parameter | Description | Default | Type | Required |
| --- | --- | --- | --- | --- |
| --baseline | CSV file containing the reference data for the comparison | None | str | Yes |
| --datasource | CSV file containing the new data to be compared with the baseline file | None | str | Yes |
| --items_yml | YML file containing the elements to analyze (processes, metrics and statistics) | None | str | Yes |
| --confidence_level | The percentage confidence level used for the statistical tests | 95 | float | No |

### Parameters restrictions

- `--baseline` and `--datasource` must indicate files in CSV format. These CSV files should contain different columns for the different metrics. There is more detailed information about this format in the `CSV format` section.

- `--confidence_level` can be a value between 0 and 100, although the most usual values are 90, 95 and 99.

- `--items_yml` must be a YML file with the following format:

```shell script
Items_to_analyze:
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

Metrics:
  CPU(%):
    Mean: 10
    Max value: 15
    Min value: 5
    Standard deviation: 5
    Variance: 10

  RSS(KB):
    Mean: 10
    Max value: 25
    Min value: 5
    Standard deviation: 5
    Variance: 5
  
  Disk_Read(B):
    Mean: 10
    Max value: 25
    Min value: 5
    Standard deviation: 5
    Variance: 5

  Disk_Written(B):
    Mean: 10
    Max value: 25
    Min value: 5
    Standard deviation: 5
    Variance: 5

  VMS(KB):
    Mean: 10
    Max value: 25
    Min value: 5
    Standard deviation: 5
    Variance: 5

  FD:
    Mean: 15
    Max value: 25
    Min value: 5
    Standard deviation: 5
    Variance: 5
  
  Read_Ops:
    Mean: 10
    Max value: 25
    Min value: 5
    Standard deviation: 5
    Variance: 5

  Write_Ops:
    Mean: 10
    Max value: 25
    Min value: 5
    Standard deviation: 5
    Variance: 5

  Disk(%):
    Mean: 10
    Max value: 25
    Min value: 5
    Standard deviation: 5
    Variance: 5
  
  USS(KB):
    Mean: 10
    Max value: 25
    Min value: 5
    Standard deviation: 5
    Variance: 5
  
  PSS(KB):
    Mean: 10
    Max value: 25
    Min value: 5
    Standard deviation: 5
    Variance: 5
  
  SWAP(KB):
    Mean: 10
    Max value: 25
    Min value: 5
    Standard deviation: 5
    Variance: 5
```

This file indicates all possible processes, metrics, and statistics to be analyzed. 

If no daemons are to be analyzed, `Daemon` must be replaced by the corresponding process to be analyzed (this will be the name of the column in the CSV file containing the processes). If you only want to analyze one process, add its name to the list, whatever it is. 

The value accompanying each statistic is the threshold (percentage) which must be exceeded in the comparison of the two data sets to detect an error. All possible values to be analyzed are contained in this example YML file.

Threshold values can be conveniently changed, and processes, metrics, or statistics can be deleted as required to make the test more concrete.

### CSV format

The CSV files must contain different columns that collect the data of the different metrics analyzed. They do not have to be metrics such as CPU, RSS or others, they simply have to be columns that collect the data you want to analyze. The only restriction here is that the name of those columns must be the same as the one indicated in the YML file in the metrics section.

It must also contain a column representing the main item to be analyzed. This can be the column of the processes to analyze, demons, or simply indicate that, for example, the item to analyze is the wazuh dashboard.

Examples of CSV files:

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

For this last example, the YML file to be inserted would be:

```shell script
Items_to_analyze:
  Item:
    - "wazuh-dashboard"

Metrics:
  Seconds:
    Mean: 20
    Max value: 5
```

### Example

```shell script
python3 -m pytest test_data_analyzer_module.py --baseline ./data/4.8.0-rc4-vdr.csv --datasource ./data/4.8.1-rc2-vdr.csv --items_yaml ./data/items_to_compare.yml --html=report.html
```

- Result: [report.zip](https://github.com/user-attachments/files/16454337/report.zip)
