import pytest
from wazuh_testing.scripts.statistical_data_analyzer import data_comparison_test, comparison_basic_statistics

def test_comparison(data):
    baseline, datasource = data
    
    daemons = baseline['Daemon'].unique()
    for daemon in daemons:
        
