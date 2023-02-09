"""Utils to generate sample data to AWS"""
import csv
import json
from datetime import datetime
from os.path import join
from io import StringIO
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

    def get_filename(self) -> str:
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

    def get_filename(self) -> str:
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
    BASE_PATH = join(cons.AWS_LOGS, cons.RANDOM_ACCOUNT_ID, cons.ELASTIC_LOAD_BALANCING, cons.US_EAST_1_REGION)
    BASE_FILE_NAME = f'{cons.RANDOM_ACCOUNT_ID}_{cons.ELASTIC_LOAD_BALANCING}_{cons.US_EAST_1_REGION}_'

    def get_filename(self) -> str:
        """Return the filename in the ALB format.

        Example:
            <prefix>/AWSLogs/<suffix>/<organization_id>/<account_id>/elasticloadbalancing/<region>/<year>/<month>/<day>

        Returns:
            str: Synthetic filename.
        """
        now = datetime.utcnow()
        path = join(self.BASE_PATH, now.strftime(cons.PATH_DATE_FORMAT))
        name = (
            f'{self.BASE_FILE_NAME}_app.ALB-qatests_{now.strftime(cons.FILENAME_DATE_FORMAT)}_{abs(hash(now))}_'
            f'{get_random_ip()}_pczeay_{cons.LOG_EXT}'
        )

        return join(path, name)

    def get_data_sample(self) -> str:
        """Return a sample of data according to the ALB format.

        Returns:
            str: Synthetic data.
        """
        now = datetime.utcnow()
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


class CLBDataGenerator(DataGenerator):
    BASE_PATH = join(cons.AWS_LOGS, cons.RANDOM_ACCOUNT_ID, cons.ELASTIC_LOAD_BALANCING, cons.US_EAST_1_REGION)
    BASE_FILE_NAME = f'{cons.RANDOM_ACCOUNT_ID}_{cons.ELASTIC_LOAD_BALANCING}_{cons.US_EAST_1_REGION}_'

    def get_filename(self) -> str:
        """Return the filename in the CLB format.

        Example:
            <prefix>/AWSLogs/<suffix>/<organization_id>/<account_id>/elasticloadbalancing/<region>/<year>/<month>/<day>

        Returns:
            str: Synthetic filename.
        """
        now = datetime.utcnow()
        path = join(self.BASE_PATH, now.strftime(cons.PATH_DATE_FORMAT))
        name = (
            f'{self.BASE_FILE_NAME}qatests-APIClassi_{now.strftime(cons.FILENAME_DATE_FORMAT)}_{abs(hash(now))}_'
            f'{get_random_ip()}{cons.LOG_EXT}'
        )

        return join(path, name)

    def get_data_sample(self) -> str:
        """Return a sample of data according to the CLB format.

        Returns:
            str: Synthetic data.
        """
        now = datetime.utcnow()
        data = []
        for _ in range(5):
            data.append(
                [
                    now.strftime(cons.ALB_DATE_FORMAT),  # time
                    'qatests-APIClassi',  # elb
                    f"{get_random_ip()}:{get_random_port()}",  # client:port
                    f"{get_random_ip()}:{get_random_port()}",  # backend:port
                    0.000628,  # request_processing_time
                    0.001,  # backend_processing_time
                    0.000015,  # response_processing_time
                    403,  # elb_status_code
                    403,  # backend_status_code
                    1071,  # received_bytes
                    2250,  # sent_bytes
                    '- - -',  # request
                    'Mozilla/5.0 (compatible; Nimbostratus-Bot/v1.3.2; http://cloudsystemnetworks.com)',  # user_agent
                    '-',  # ssl_cipher
                    '-',  # ssl_protocol
                ]
            )
        buffer = StringIO()
        csv.writer(buffer, delimiter=" ").writerows(data)

        return buffer.getvalue()


class NLBDataGenerator(DataGenerator):
    BASE_PATH = join(cons.AWS_LOGS, cons.RANDOM_ACCOUNT_ID, cons.ELASTIC_LOAD_BALANCING, cons.US_EAST_1_REGION)
    BASE_FILE_NAME = f'{cons.RANDOM_ACCOUNT_ID}_{cons.ELASTIC_LOAD_BALANCING}_{cons.US_EAST_1_REGION}_'

    def get_filename(self) -> str:
        """Return the filename in the NLB format.

        Example:
            <prefix>/AWSLogs/<suffix>/<organization_id>/<account_id>/elasticloadbalancing/<region>/<year>/<month>/<day>

        Returns:
            str: Synthetic filename.
        """
        now = datetime.utcnow()
        path = join(self.BASE_PATH, now.strftime(cons.PATH_DATE_FORMAT))
        name = (
            f'{self.BASE_FILE_NAME}net.qatests_{now.strftime(cons.FILENAME_DATE_FORMAT)}_{abs(hash(now))}_'
            f'{get_random_ip()}{cons.LOG_EXT}'
        )

        return join(path, name)

    def get_data_sample(self) -> str:
        """Return a sample of data according to the NLB format.

        Returns:
            str: Synthetic data.
        """
        now = datetime.utcnow()
        data = []
        for _ in range(5):
            data.append(
                [
                    'tls',  # type
                    '2.0',  # version
                    now.strftime(cons.ALB_DATE_FORMAT),  # time
                    'net/qatests',  # elb
                    get_random_string(16),  # listener
                    f"{get_random_ip()}:{get_random_port()}",  # client:port
                    f"{get_random_ip()}:{get_random_port()}",  # destination:port
                    17553,  # connection_time
                    0.001,  # tls_handshake_time
                    1071,  # received_bytes
                    2250,  # sent_bytes
                    '-',  # incoming_tls_alert
                    '-',  # chosen_cert_arn
                    '-',  # chosen_cert_serial
                    '-',  # tls_cipher
                    '-',  # tls_protocol_version
                    '-',  # tls_named_group
                    '-',  # domain_name
                    '-',  # alpn_fe_protocol
                    '-',  # alpn_be_protocol
                    '-',  # alpn_client_preference_list
                ]
            )
        buffer = StringIO()
        csv.writer(buffer, delimiter=" ").writerows(data)

        return buffer.getvalue()


class KMSDataGenerator(DataGenerator):
    BASE_PATH = ''
    BASE_FILE_NAME = f'firehose_kms-1-'

    def get_filename(self) -> str:
        """Return the filename in the KMS format.

        Example:
            <prefix>/<year>/<month>/<day>

        Returns:
            str: Synthetic filename.
        """
        now = datetime.utcnow()
        path = join(self.BASE_PATH, now.strftime(cons.PATH_DATE_FORMAT))
        name = f"{self.BASE_FILE_NAME}{now.strftime(cons.FILENAME_DATE_FORMAT)}_{str(uuid4())}{cons.JSON_EXT}"

        return join(path, name)

    def get_data_sample(self) -> str:
        """Return a sample of data according to the KMS format.

        Returns:
            str: Synthetic data.
        """
        return json.dumps(
            {
                'version': '0',
                'id': str(uuid4()),
                'detail-type': 'AWS API Call via CloudTrail',
                'source': 'aws.kms',
                'account': cons.RANDOM_ACCOUNT_ID,
                'time': '2018-11-07T17:27:01Z',
                'region': cons.US_EAST_1_REGION,
                'resources': [],
                'detail': {
                    'eventVersion': '1.05',
                    'userIdentity': {
                        'type': 'IAMUser',
                        'principalId': get_random_string(20),
                        'arn': f"arn:aws:iam::{cons.RANDOM_ACCOUNT_ID}:user/fake.user",
                        'accountId': cons.RANDOM_ACCOUNT_ID,
                        'accessKeyId': get_random_string(20),
                        'userName': 'fake.user',
                        'sessionContext': {
                            'attributes': {
                                'mfaAuthenticated': 'false',
                                'creationDate': '2018-11-07T07:53:47Z'
                            }
                        },
                        'invokedBy': 'secretsmanager.amazonaws.com'
                    },
                    'eventTime': '2018-11-07T17:27:01Z',
                    'eventSource': 'kms.amazonaws.com',
                    'eventName': 'GenerateDataKey',
                    'awsRegion': cons.RANDOM_ACCOUNT_ID,
                    'sourceIPAddress': 'secretsmanager.amazonaws.com',
                    'userAgent': 'secretsmanager.amazonaws.com',
                    'requestParameters': {
                        'keySpec': 'AES_256',
                        'encryptionContext': {
                            'SecretARN': f"arn:aws:secretsmanager:us-east-1:{cons.RANDOM_ACCOUNT_ID}:secret:test-aws",
                            'SecretVersionId': str(uuid4())
                        },
                        'keyId': 'alias/aws/secretsmanager'
                    },
                    'responseElements': None,
                    'requestID': str(uuid4()),
                    'eventID': str(uuid4()),
                    'readOnly': True,
                    'resources': [
                        {
                            'ARN': f"arn:aws:kms:us-east-1:{cons.RANDOM_ACCOUNT_ID}:key/{str(uuid4())}",
                            'accountId': cons.RANDOM_ACCOUNT_ID,
                            'type': 'AWS::KMS::Key'
                        }
                    ],
                    'eventType': 'AwsApiCall',
                    'vpcEndpointId': f"vpce-{get_random_string(17)}"
                }
            }
        )


class MacieDataGenerator(DataGenerator):
    BASE_PATH = ''
    BASE_FILE_NAME = 'firehose_macie-1-'

    def get_filename(self) -> str:
        """Return the filename in the Macie format

        Example:
            <prefix>/<year>/<month>/<day>

        Returns:
            str: Synthetic filename.
        """
        now = datetime.utcnow()
        path = join(self.BASE_PATH, now.strftime(cons.PATH_DATE_FORMAT))
        name = f"{self.BASE_FILE_NAME}{now.strftime(cons.FILENAME_DATE_FORMAT)}_{str(uuid4())}{cons.JSON_EXT}"

        return join(path, name)

    def get_data_sample(self) -> str:
        """Return a sample of data according to the Macie format.

        Returns:
            str: Synthetic data.
        """

        return json.dumps(
            {
                'version': '0',
                'id': str(uuid4()),
                'detail-type': 'Macie Alert',
                'source': 'aws.macie',
                'account': cons.RANDOM_ACCOUNT_ID,
                'time': '2021-01-01T00:20:42Z',
                'region': 'us-east-1',
                'resources': [
                    f"arn:aws:macie:us-east-1:{cons.RANDOM_ACCOUNT_ID}:trigger/{str(uuid4())}/alert",
                    f"arn:aws:macie:us-east-1:{cons.RANDOM_ACCOUNT_ID}:trigger/{str(uuid4())}"
                ],
                'detail': {
                    'notification-type': 'ALERT_CREATED',
                    'tags': [
                        'Open Permissions',
                        'Basic Alert'
                    ],
                    'name': 'S3 Bucket IAM policy grants global read rights',
                    'severity': 'CRITICAL',
                    'url': 'https://mt.us-east-1.macie.aws.amazon.com/posts/arn%3Aaws%3Amacie%3Aus-east-1',
                    'alert-arn': f"arn:aws:macie:us-east-1:{cons.RANDOM_ACCOUNT_ID}:trigger/{str(uuid4())}/alert",
                    'risk-score': 9,
                    'created-at': '2021-01-01T00:20:42.364509',
                    'actor': 'resources.wazuh.com',
                    'summary': {
                        'Description': 'S3 Bucket uses IAM policy to grant read rights to Everyone.',
                        'Bucket': {
                            'resources.wazuh.com': 1
                        },
                        'Record Count': 1,
                        'ACL': {
                            'resources.wazuh.com': [
                                {
                                    'Owner': {
                                        'DisplayName': 'wazuh',
                                        'ID': get_random_string(64),
                                    },
                                    'Grants': [
                                        {
                                            'Grantee': {
                                                'Type': 'CanonicalUser',
                                                'DisplayName': 'wazuh',
                                                'ID': get_random_string(64),
                                            },
                                            'Permission': 'FULL_CONTROL'
                                        },
                                        {
                                            'Grantee': {
                                                'Type': 'Group',
                                                'URI': 'http://acs.amazonaws.com/groups/global/AllUsers'
                                            },
                                            'Permission': 'READ'
                                        }
                                    ]
                                }
                            ]
                        },
                        'Event Count': 1,
                        'Timestamps': {
                            '2021-01-01T00:11:49.171020Z': 1
                        },
                        'recipientAccountId': {
                            cons.RANDOM_ACCOUNT_ID: 1
                        }
                    },
                    'trigger': {
                        'rule-arn': (
                            f"arn:aws:macie:us-east-1:{cons.RANDOM_ACCOUNT_ID}:trigger/b731d9ffb1fe61508d4a478c92efa666"
                        ),
                        'alert-type': 'basic',
                        'created-at': '2020-12-29 16:36:17.412000+00:00',
                        'description': 'S3 Bucket uses IAM policy to grant read rights to Everyone.',
                        'risk': 9
                    }
                }
            }
        )


# Maps bucket type with corresponding data generator
buckets_data_mapping = {
    cons.CLOUD_TRAIL_TYPE: CloudTrailDataGenerator,
    cons.VPC_FLOW_TYPE: VPCDataGenerator,
    cons.CONFIG_TYPE: ConfigDataGenerator,
    cons.ALB_TYPE: ALBDataGenerator,
    cons.CLB_TYPE: CLBDataGenerator,
    cons.NLB_TYPE: NLBDataGenerator,
    cons.KMS_TYPE: KMSDataGenerator,
    cons.MACIE_TYPE: MacieDataGenerator,
}


def get_data_generator(bucket_type: str, bucket_name: str) -> DataGenerator:
    """Given the bucket type return the correspondant data generator instance.

    Args:
        bucket_type (str): Bucket type to match the data generator.
        bucket_name (str): Bucket name to match in case of custom types.

    Returns:
        DataGenerator: Data generator for the given bucket.
    """
    if bucket_type == cons.CUSTOM_TYPE:
        bucket_type = bucket_name.split('-')[1]

    return buckets_data_mapping[bucket_type]()
