from pathlib import Path

from wazuh_testing import WAZUH_PATH

AWS_MODULE_PATH = Path(WAZUH_PATH, 'wodles', 'aws')
S3_CLOUDTRAIL_DB_PATH = Path(AWS_MODULE_PATH, 's3_cloudtrail.db')
AWS_SERVICES_DB_PATH = Path(AWS_MODULE_PATH, 'aws_services.db')

AWS_LOGS = 'AWSLogs'
RANDOM_ACCOUNT_ID = '819751203818'
CLOUDTRAIL = 'CloudTrail'
GUARDDUTY = 'GuardDuty'
VPC_FLOW_LOGS = "vpcflowlogs"
FLOW_LOG_ID = "fl-0754d951c16f517fa"
CONFIG = 'Config'
ELASTIC_LOAD_BALANCING = 'elasticloadbalancing'
SERVER_ACCESS_TABLE_NAME = 's3_server_access'

EVENT_TIME_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
PATH_DATE_FORMAT = '%Y/%m/%d'
PATH_DATE_NO_PADED_FORMAT = '%Y/%-m/%-d'
FILENAME_DATE_FORMAT = '%Y%m%dT%H%MZ'
ALB_DATE_FORMAT = '%Y-%m-%dT%H:%M:%fZ'

US_EAST_1_REGION = 'us-east-1'

JSON_EXT = '.json'
LOG_EXT = '.log'
JSON_GZ_EXT = '.jsonl.gz'

# Bucket types
CLOUD_TRAIL_TYPE = 'cloudtrail'
VPC_FLOW_TYPE = 'vpcflow'
CONFIG_TYPE = 'config'
ALB_TYPE = 'alb'
CLB_TYPE = 'clb'
NLB_TYPE = 'nlb'
KMS_TYPE = 'kms'
MACIE_TYPE = 'macie'
KMS_TYPE = 'kms'
TRUSTED_ADVISOR_TYPE = 'trusted'
CUSTOM_TYPE = 'custom'
GUARD_DUTY_TYPE = 'guardduty'
NATIVE_GUARD_DUTY_TYPE = 'native-guardduty'
WAF_TYPE = 'waf'
SERVER_ACCESS = 'server_access'
