# Statistical Data Analyzer Module

This module contains a basic test that allows you to perform statistical analysis and calculations on two data sets and to make comparisons between them. This allows to detect significant differences between the two sets automatically.

This test uses t-Student, Levene and ANOVA tests to detect possible significant differences in the metrics of the data sets. If such differences exist, comparisons are made between the main statistics with respect to a threshold value which, if exceeded, is marked as an error and reported conveniently.

The analysis is performed specifically for the demons, metrics and statistics that are specified in a YML file, in which the threshold value for each statistic will also be indicated.

## Initial setup

To run these tests, we need the wazuh-testing package. So first, we need to install all these Python dependencies, we can use this command:

```shell script
pip3 install -r requirements.txt
```

Then, we need to install the package:

```shell script
cd deps/wazuh_testing
python3 setup.py install
```

## Pytest

To run the tests, we will need to use the following command:

```shell script
python3 -m pytest test_data_analyzer_module.py --baseline <baseline_csv_file> --datasource <data_csv_file> --items_yaml <yml_file> --<options>
```

### Parameters

| Parameter | Description | Default | Type | Required |
| --- | --- | --- | --- | --- |
| --baseline | CSV file containing the reference data for the comparison | None | str | Yes |
| --datasource | CSV file containing the new data to be compared with the baseline file | None | str | Yes |
| --items_yml | YML file containing the elements to analyze (daemons, metrics and statistics) | None | str | Yes |
| --confidence_level | The percentage confidence level used for the statistical tests | 95 | float | No |

### Parameters restrictions

- `--baseline` and `--datasource` must indicate files in CSV format

- `--confidence_level` can be a value between 0 and 100, although the most usual values are 90, 95 and 99.

- `--items_yml` must be a YML file with the following format:

```shell script
Daemons:
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

This file indicates all possible daemons, metrics, and statistics to be analyzed. The value accompanying each statistic is the threshold (percentage) which must be exceeded in the comparison of the two data sets to detect an error. All possible values to be analyzed are contained in this example YML file.

Threshold values can be conveniently changed, and demons, metrics, or statistics can be deleted as required to make the test more concrete.

### Example

```shell script
python3 -m pytest test_data_analyzer_module.py --baseline ./data/4.8.0-rc4-vdr.csv --datasource ./data/4.8.1-rc2-vdr.csv --items_yaml ./data/items_to_compare.yml --html=report.html
```

- Result: [report.zip](https://github.com/user-attachments/files/16424221/report.zip)