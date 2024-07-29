# Statistical Data Analyzer Module

This module contains a basic test that allows you to perform statistical analysis and calculations on two sets of data and to make comparisons between them. This allows to detect significant differences between the two sets automatically.

This test uses t-Student, Levene and ANOVA tests to detect possible significant differences in the metrics of the data sets. If such differences exist, comparisons are made between the main statistics with respect to a threshold value which, if exceeded, is marked as an error and reported conveniently.

The analysis is performed specifically for the demons, metrics and statistics that are specified in a YML file, in which the threshold value for each statistic will also be indicated.

## Initial setup

To run these tests a **Linux** machine will be required.

In addition, we need the wazuh-testing package. So first, we need to install all these Python dependencies, we can use this command:

```console
pip3 install -r requirements.txt
```

Then, we need to install the package:

```console
cd deps/wazuh_testing
python3 setup.py install
```

## Pytest

To run the tests, we will need to use the following command:

```console
python3 -m pytest test_data_analyzer_module.py --baseline <baseline_csv_file> --datasource <data_csv_file> --items_yaml <yml_file> --<options>
```

### Parameters



### Parameters restrictions



### Example

```console
python3 -m pytest test_data_analyzer_module.py --baseline ./data/4.8.0-rc4-vdr.csv --datasource ./data/4.8.1-rc2-vdr.csv --items_yaml ./data/items_to_compare.yml --html=report.html
```
