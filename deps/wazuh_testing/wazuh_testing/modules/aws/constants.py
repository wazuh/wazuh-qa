from pathlib import Path

from wazuh_testing import WAZUH_PATH

AWS_MODULE_PATH = Path(WAZUH_PATH, 'wodles', 'aws')
S3_CLOUDTRAIL_DB_PATH = Path(AWS_MODULE_PATH, 's3_cloudtrail.db')

AWS_LOGS = 'AWSLogs'
RANDOM_ACCOUNT_ID = '819751203818'
CLOUDTRAIL = 'CloudTrail'
VPC_FLOW_LOGS = "vpcflowlogs"
FLOW_LOG_ID = "fl-0754d951c16f517fa"
CONFIG = 'Config'

EVENT_TIME_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
PATH_DATE_FORMAT = '%Y/%m/%d'
FILENAME_DATE_FORMAT = '%Y%m%dT%H%MZ'

US_EAST_1_REGION = 'us-east-1'

JSON_EXT = '.json'
LOG_EXT = '.log'

# Bucket types
CLOUD_TRAIL_TYPE = 'cloudtrail'
VPC_FLOW_TYPE = 'vpcflow'
CONFIG_TYPE = 'config'
