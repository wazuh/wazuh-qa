from datetime import datetime
import os
import pytest
import psutil
import yaml
from unittest.mock import patch, MagicMock
from process_resource_monitoring.disk_usage_tracker import DiskUsageTracker

def load_yaml_data(file_name: str) -> dict:
    """Load YAML data from a file."""
    file_path = os.path.join(os.path.dirname(__file__), file_name)
    with open(file_path, 'r') as f:
        return yaml.safe_load(f)

@pytest.fixture(scope='module')
def test_data():
    return load_yaml_data('test_data.yml')

@patch('os.path.getsize')
@patch('os.path.getmtime')
@patch('os.path.getatime')
@patch('os.path.getctime')
@patch('psutil.disk_usage')
def test_get_file_info(mock_disk_usage, mock_getctime, mock_getatime, mock_getmtime, mock_getsize, test_data):
    # Access test data
    file_path = test_data['test_file_info']['file_path']
    value_unit = test_data['test_file_info']['value_unit']
    expected_info = test_data['test_file_info']['expected_info']

    # Convert size to bytes
    unit_multiplier = DiskUsageTracker._DATA_UNITS[value_unit]
    mock_file_size = expected_info[f'Size({value_unit})'] * (1024 ** unit_multiplier)
    
    # Define mock values
    mock_mod_time = datetime.strptime(expected_info['Mod_time'], '%d/%m/%Y-%H:%M:%S.%f').timestamp()
    mock_acc_time = datetime.strptime(expected_info['Acc_time'], '%d/%m/%Y-%H:%M:%S.%f').timestamp()
    mock_creat_time = datetime.strptime(expected_info['Creat_time'], '%d/%m/%Y-%H:%M:%S.%f').timestamp()

    # Create a mock object for disk usage
    mock_disk_usage_obj = MagicMock()
    mock_disk_usage_obj.total = psutil.disk_usage('/').total
    mock_disk_usage_obj.percent = expected_info['Usage(%)']

    # Set mock values
    mock_getsize.return_value = mock_file_size
    mock_disk_usage.return_value = mock_disk_usage_obj
    mock_getmtime.return_value = mock_mod_time
    mock_getatime.return_value = mock_acc_time
    mock_getctime.return_value = mock_creat_time

    # Instantiate the DiskUsageTracker with test data
    tracker = DiskUsageTracker(file_path=file_path, value_unit=value_unit)

    # Call the method to be tested
    file_info = tracker.get_file_info()

    # Validate the expected values
    assert file_info['File'] == expected_info['File']
    assert abs(file_info[f'Size({value_unit})'] - expected_info[f'Size({value_unit})']) < 0.01
    assert abs(file_info['Usage(%)'] - expected_info['Usage(%)']) < 0.01
    assert file_info['Mod_time'] == expected_info['Mod_time']
    assert file_info['Acc_time'] == expected_info['Acc_time']
    assert file_info['Creat_time'] == expected_info['Creat_time']
