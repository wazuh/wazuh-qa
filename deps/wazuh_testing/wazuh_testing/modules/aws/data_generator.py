"""Utils to generate sample data to AWS"""
import csv
import json
from datetime import datetime
from io import StringIO
from os.path import join
from uuid import uuid4

from wazuh_testing.tools.utils import get_random_ip, get_random_port, get_random_string

from . import constants as cons


def get_random_interface_id() -> str:
    """Return a random interface ID."""
    return f"eni-{get_random_string(17)}"


class DataGenerator:
    BASE_PATH = ''
    BASE_FILE_NAME = ''

    def get_filename(self, *args, **kwargs) -> str:
        """Return the filename according to the integration format.

        Returns:
            str: Synthetic filename.
        """
        raise NotImplementedError()

    def get_data_sample(self, *args, **kwargs) -> dict:
        """Return a sample of data according to the integration format.

        Returns:
            dict: Synthetic data.
        """
        raise NotImplementedError()


class CloudTrailDataGenerator(DataGenerator):
    BASE_PATH = join(cons.AWS_LOGS, cons.RANDOM_ACCOUNT_ID, cons.CLOUDTRAIL, cons.US_EAST_1_REGION)
    BASE_FILE_NAME = f"{cons.RANDOM_ACCOUNT_ID}_{cons.CLOUDTRAIL}_{cons.US_EAST_1_REGION}_"

    def get_filename(self, *args, **kwargs) -> str:
        """Return the filename in the cloudtrail format.

        Example:
            <prefix>/AWSLogs/<suffix>/<organization_id>/<account_id>/CloudTrail/<region>/<year>/<month>/<day>

        Returns:
            str: Synthetic filename.
        """
        now = datetime.utcnow()
        path = join(self.BASE_PATH, now.strftime(cons.PATH_DATE_FORMAT))
        name = f"{self.BASE_FILE_NAME}{now.strftime(cons.FILENAME_DATE_FORMAT)}_{abs(hash(now))}{cons.JSON_EXT}"

        return join(path, name)

    def get_data_sample(self) -> str:
        """Return a sample of data according to the cloudtrail format.

        Returns:
            str: Synthetic data.
        """
        return json.dumps({
            'Records': [
                {
                    'eventVersion': '1.08',
                    'userIdentity': {
                        'type': 'AWSService',
                        'invokedBy': 'ec2.amazonaws.com'
                    },
                    'eventTime': datetime.utcnow().strftime(cons.EVENT_TIME_FORMAT),
                    'eventSource': 'sts.amazonaws.com',
                    'eventName': 'AssumeRole',
                    'awsRegion': cons.US_EAST_1_REGION,
                    'sourceIPAddress': 'ec2.amazonaws.com',
                    'userAgent': 'ec2.amazonaws.com',
                    'requestParameters': {
                        'roleArn': f"arn:aws:iam::{cons.RANDOM_ACCOUNT_ID}:role/demo-415-v2-InstanceRole-1FB0FMP2EXOKN",
                        'roleSessionName': 'i-0e9ddef5daf05c7df'
                    },
                    'responseElements': {
                        'credentials': {
                            'accessKeyId': 'ASIASNL6BLJL7ZA3J6WP',
                            'sessionToken': str(uuid4()),
                            'expiration': 'Dec 23, 2021, 3:51:35 PM'
                        }
                    },
                    'requestID': str(uuid4()),
                    'eventID': str(uuid4()),
                    'readOnly': True,
                    'resources': [
                        {
                            'accountId': cons.RANDOM_ACCOUNT_ID,
                            'type': 'AWS::IAM::Role',
                            'ARN': f"arn:aws:iam::{cons.RANDOM_ACCOUNT_ID}:role/demo-415-v2-InstanceRole-1FB0FMP2EXOKN"
                        }
                    ],
                    'eventType': 'AwsApiCall',
                    'managementEvent': True,
                    'eventCategory': 'Management',
                    'recipientAccountId': cons.RANDOM_ACCOUNT_ID,
                    'sharedEventID': str(uuid4())
                }
            ]
        })


class VPCDataGenerator(DataGenerator):
    BASE_PATH = join(cons.AWS_LOGS, cons.RANDOM_ACCOUNT_ID, cons.VPC_FLOW_LOGS, cons.US_EAST_1_REGION)
    BASE_FILE_NAME = f'{cons.RANDOM_ACCOUNT_ID}_{cons.VPC_FLOW_LOGS}_{cons.US_EAST_1_REGION}_'

    def get_filename(self) -> str:
        """Return the filename in the VPC format.

        Example:
            <prefix>/AWSLogs/<suffix>/<organization_id>/<account_id>/vpcflowlogs/<region>/<year>/<month>/<day>

        Returns:
            str: Synthetic filename.
        """
        now = datetime.utcnow()
        path = join(self.BASE_PATH, now.strftime(cons.PATH_DATE_FORMAT))
        name = (
            f'{self.BASE_FILE_NAME}{cons.FLOW_LOG_ID}_{now.strftime(cons.FILENAME_DATE_FORMAT)}_{abs(hash(now))}'
            f'{cons.LOG_EXT}'
        )

        return join(path, name)

    def get_data_sample(self) -> str:
        """Return a sample of data according to the VPC format.

        Returns:
            str: Synthetic data.
        """
        data = [
            [
                "version", "account-id", "interface-id", "srcaddr", "dstaddr", "srcport", "dstport", "protocol",
                "packets", "bytes", "start", "end", "action", "log-status"
            ]
        ]

        for _ in range(5):
            data.append(
                [
                    "2", cons.RANDOM_ACCOUNT_ID, get_random_interface_id(), get_random_ip(), get_random_ip(),
                    get_random_port(), get_random_port(), "6", "39", "4698", "1622505433", "1622505730", "ACCEPT", "OK"
                ]
            )
        buffer = StringIO()
        csv.writer(buffer, delimiter=" ").writerows(data)

        return buffer.getvalue()


class ConfigDataGenerator(DataGenerator):
    BASE_PATH = join(cons.AWS_LOGS, cons.RANDOM_ACCOUNT_ID, cons.CONFIG, cons.US_EAST_1_REGION)
    BASE_FILE_NAME = f"{cons.RANDOM_ACCOUNT_ID}_{cons.CONFIG}_{cons.US_EAST_1_REGION}_ConfigHistory_AWS_"

    def get_filename(self, prefix=None, **kwargs) -> str:
        """Return the filename in the Config format.

        Example:
            <prefix>/AWSLogs/<suffix>/<organization_id>/<account_id>/Config/<region>/<year>/<month>/<day>

        Returns:
            str: Synthetic filename.
        """
        now = datetime.utcnow()
        path = join(self.BASE_PATH, now.strftime(cons.PATH_DATE_NO_PADED_FORMAT))
        name = f"{self.BASE_FILE_NAME}{now.strftime(cons.FILENAME_DATE_FORMAT)}_{abs(hash(now))}{cons.JSON_EXT}"

        return join(path, name)

    def get_data_sample(self) -> str:
        """Return a sample of data according to the Config format.

        Returns:
            str: Synthetic data.
        """
        return json.dumps({
            'fileVersion': '1.0',
            'configurationItems': [
                {
                    'relatedEvents': [],
                    'relationships': [
                        {
                            'resourceId': f"vol-{get_random_string(17)}",
                            'resourceType': 'AWS::EC2::Volume',
                            'name': 'Is associated with '
                        }
                    ],
                    'configuration': {
                        'complianceType': 'NON_COMPLIANT',
                        'targetResourceId': f"vol-{get_random_string(17)}",
                        'targetResourceType': 'AWS::EC2::Volume',
                        'configRuleList': [
                            {
                                'configRuleArn': (
                                    f"arn:aws:config:us-east-1:{cons.RANDOM_ACCOUNT_ID}:config-rule/"
                                    'config-rule-b1eqqf'),
                                'configRuleId': 'config-rule-b1eqqf',
                                'configRuleName': 'encrypted-volumes',
                                'complianceType': 'NON_COMPLIANT'
                            }
                        ]
                    },
                    'supplementaryConfiguration': {},
                    'tags': {},
                    'configurationItemVersion': '1.3',
                    'configurationItemCaptureTime': '2020-06-01T02:12:37.713Z',
                    'configurationStateId': 1590977557713,
                    'awsAccountId': cons.RANDOM_ACCOUNT_ID,
                    'configurationItemStatus': 'ResourceDiscovered',
                    'resourceType': 'AWS::Config::ResourceCompliance',
                    'resourceId': f"AWS::EC2::Volume/vol-{get_random_string(17)}",
                    'awsRegion': 'us-east-1',
                    'configurationStateMd5Hash': ''
                }
            ]
        })


class ALBDataGenerator(DataGenerator):
    BASE_PATH = f'{cons.AWS_LOGS}/{cons.RANDOM_ACCOUNT_ID}/{cons.ELASTICLOADBALANCING}/{cons.US_EAST_1_REGION}/'
    BASE_FILE_NAME = f'{cons.RANDOM_ACCOUNT_ID}_{cons.ELASTICLOADBALANCING}_{cons.US_EAST_1_REGION}_'

    def get_filename(self, prefix=None, **kwargs) -> str:
        """Return the filename in the cloudtrail format
        <prefix>/AWSLogs/<suffix>/<organization_id>/<account_id>/elasticloadbalancing/<region>/<year>/<month>/<day>
        """
        now = datetime.now()
        path = f'{self.BASE_PATH}{now.strftime(cons.PATH_DATE_FORMAT)}/'
        name = (
            f'{self.BASE_FILE_NAME}_app.ALB-qatests_{now.strftime(cons.FILENAME_DATE_FORMAT)}_{abs(hash(now))}_'
            f'{get_random_ip()}_pczeay_{cons.LOG_EXT}'
        )

        return f'{path}{name}'

    def get_data_sample(self) -> str:
        now = datetime.now()
        data = []

        for _ in range(5):
            data.append(
                [
                    "http",  # type
                    now.strftime(cons.ALB_DATE_FORMAT),  # time
                    'app/ALB-qatests',  # elb
                    f"{get_random_ip()}:{get_random_port()}",  # client:port
                    f"{get_random_ip()}:{get_random_port()}",  # target:port
                    0.001,  # request_processing_time
                    0.001,  # target_processing_time
                    0.000,  # response_processing_time
                    403,  # elb_status_code
                    403,  # target_status_code
                    136,  # received_bytes
                    5173,  # sent_bytes
                    f"GET http://{get_random_ip()}:80/ HTTP/1.1",  # request
                    'Mozilla/5.0 (compatible; Nimbostratus-Bot/v1.3.2; http://cloudsystemnetworks.com)',  # user_agent
                    '-',  # ssl_cipher
                    '-',  # ssl_protocol
                    # target_group_arn
                    f"arn:aws:elasticloadbalancing:{cons.US_EAST_1_REGION}:{cons.RANDOM_ACCOUNT_ID}:targetgroup/EC2/",
                    f"Root=1-5fbc4c52-{get_random_string(24)}",  # trace_id
                    "-",  # domain_name
                    "-",  # chosen_cert_arn
                    0,  # matched_rule_priority
                    now.strftime(cons.ALB_DATE_FORMAT),  # request_creation_time
                    "forward",  # actions_executed
                    "-",  # redirect_url
                    "-",  # error_reason
                    f"{get_random_ip()}:{get_random_port()} {get_random_ip()}:{get_random_port()}",  # target:port_list
                    "403",  # target_status_code_list
                    "-",  # classification
                    "-"  # classification_reason
                ]
            )
        buffer = StringIO()
        csv.writer(buffer, delimiter=" ").writerows(data)

        return buffer.getvalue()


# Maps bucket type with corresponding data generator
buckets_data_mapping = {
    cons.CLOUD_TRAIL_TYPE: CloudTrailDataGenerator,
    cons.VPC_FLOW_TYPE: VPCDataGenerator,
    cons.CONFIG_TYPE: ConfigDataGenerator,
    cons.ALB_TYPE: ALBDataGenerator
}


def get_data_generator(bucket_type: str) -> DataGenerator:
    """Given the bucket type return the correspondant data generator instance.

    Args:
        bucket_type (str): Bucket type to match the data generator.

    Returns:
        DataGenerator: Data generator for the given bucket.
    """
    return buckets_data_mapping[bucket_type]()
