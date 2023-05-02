"""Utils to generate sample data to AWS"""
import csv
import json
from datetime import datetime
from io import StringIO
from os.path import join
from uuid import uuid4

from wazuh_testing.modules import aws as cons
from wazuh_testing.tools.utils import get_random_ip, get_random_port, get_random_string


def get_random_interface_id():
    """Return a random interface ID that match with the AWS format."""
    return f"eni-{get_random_string(17)}"


class DataGenerator:
    BASE_PATH = ''
    BASE_FILE_NAME = ''

    compress = False

    def get_filename(self, *args, **kwargs):
        """Return the filename according to the integration format.

        Returns:
            str: Synthetic filename.
        """
        raise NotImplementedError()

    def get_data_sample(self, *args, **kwargs):
        """Return a sample of data according to the integration format.

        Returns:
            dict: Synthetic data.
        """
        raise NotImplementedError()


class CloudTrailDataGenerator(DataGenerator):
    BASE_PATH = join(cons.AWS_LOGS, cons.RANDOM_ACCOUNT_ID, cons.CLOUDTRAIL, cons.US_EAST_1_REGION)
    BASE_FILE_NAME = f"{cons.RANDOM_ACCOUNT_ID}_{cons.CLOUDTRAIL}_{cons.US_EAST_1_REGION}_"

    def get_filename(self):
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

    def get_data_sample(self):
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
    BASE_FILE_NAME = f"{cons.RANDOM_ACCOUNT_ID}_{cons.VPC_FLOW_LOGS}_{cons.US_EAST_1_REGION}_"

    def get_filename(self):
        """Return the filename in the VPC format.

        Example:
            <prefix>/AWSLogs/<suffix>/<organization_id>/<account_id>/vpcflowlogs/<region>/<year>/<month>/<day>

        Returns:
            str: Synthetic filename.
        """
        now = datetime.utcnow()
        path = join(self.BASE_PATH, now.strftime(cons.PATH_DATE_FORMAT))
        name = (
            f"{self.BASE_FILE_NAME}{cons.FLOW_LOG_ID}_{now.strftime(cons.FILENAME_DATE_FORMAT)}_{abs(hash(now))}"
            f"{cons.LOG_EXT}"
        )

        return join(path, name)

    def get_data_sample(self):
        """Return a sample of data according to the VPC format.

        Returns:
            str: Synthetic data.
        """
        data = [
            [
                'version', 'account-id', 'interface-id', 'srcaddr', 'dstaddr', 'srcport', 'dstport', 'protocol',
                'packets', 'bytes', 'start', 'end', 'action', 'log-status'
            ]
        ]

        for _ in range(5):
            data.append(
                [
                    '2', cons.RANDOM_ACCOUNT_ID, get_random_interface_id(), get_random_ip(), get_random_ip(),
                    get_random_port(), get_random_port(), '6', '39', '4698', '1622505433', '1622505730', 'ACCEPT', 'OK'
                ]
            )
        buffer = StringIO()
        csv.writer(buffer, delimiter=' ').writerows(data)

        return buffer.getvalue()


class ConfigDataGenerator(DataGenerator):
    BASE_PATH = join(cons.AWS_LOGS, cons.RANDOM_ACCOUNT_ID, cons.CONFIG, cons.US_EAST_1_REGION)
    BASE_FILE_NAME = f"{cons.RANDOM_ACCOUNT_ID}_{cons.CONFIG}_{cons.US_EAST_1_REGION}_ConfigHistory_AWS_"

    def get_filename(self):
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

    def get_data_sample(self):
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
    BASE_FILE_NAME = f"{cons.RANDOM_ACCOUNT_ID}_{cons.ELASTIC_LOAD_BALANCING}_{cons.US_EAST_1_REGION}_"

    def get_filename(self):
        """Return the filename in the ALB format.

        Example:
            <prefix>/AWSLogs/<suffix>/<organization_id>/<account_id>/elasticloadbalancing/<region>/<year>/<month>/<day>

        Returns:
            str: Synthetic filename.
        """
        now = datetime.utcnow()
        path = join(self.BASE_PATH, now.strftime(cons.PATH_DATE_FORMAT))
        name = (
            f"{self.BASE_FILE_NAME}_app.ALB-qatests_{now.strftime(cons.FILENAME_DATE_FORMAT)}_{abs(hash(now))}_"
            f"{get_random_ip()}_pczeay_{cons.LOG_EXT}"
        )

        return join(path, name)

    def get_data_sample(self):
        """Return a sample of data according to the ALB format.

        Returns:
            str: Synthetic data.
        """
        now = datetime.utcnow()
        data = []

        for _ in range(5):
            data.append(
                [
                    'http',  # type
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
                    '-',  # domain_name
                    '-',  # chosen_cert_arn
                    0,  # matched_rule_priority
                    now.strftime(cons.ALB_DATE_FORMAT),  # request_creation_time
                    'forward',  # actions_executed
                    '-',  # redirect_url
                    '-',  # error_reason
                    f"{get_random_ip()}:{get_random_port()} {get_random_ip()}:{get_random_port()}",  # target:port_list
                    '403',  # target_status_code_list
                    '-',  # classification
                    '-'  # classification_reason
                ]
            )
        buffer = StringIO()
        csv.writer(buffer, delimiter=' ').writerows(data)

        return buffer.getvalue()


class CLBDataGenerator(DataGenerator):
    BASE_PATH = join(cons.AWS_LOGS, cons.RANDOM_ACCOUNT_ID, cons.ELASTIC_LOAD_BALANCING, cons.US_EAST_1_REGION)
    BASE_FILE_NAME = f"{cons.RANDOM_ACCOUNT_ID}_{cons.ELASTIC_LOAD_BALANCING}_{cons.US_EAST_1_REGION}_"

    def get_filename(self):
        """Return the filename in the CLB format.

        Example:
            <prefix>/AWSLogs/<suffix>/<organization_id>/<account_id>/elasticloadbalancing/<region>/<year>/<month>/<day>

        Returns:
            str: Synthetic filename.
        """
        now = datetime.utcnow()
        path = join(self.BASE_PATH, now.strftime(cons.PATH_DATE_FORMAT))
        name = (
            f"{self.BASE_FILE_NAME}qatests-APIClassi_{now.strftime(cons.FILENAME_DATE_FORMAT)}_{abs(hash(now))}_"
            f"{get_random_ip()}{cons.LOG_EXT}"
        )

        return join(path, name)

    def get_data_sample(self):
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
        csv.writer(buffer, delimiter=' ').writerows(data)

        return buffer.getvalue()


class NLBDataGenerator(DataGenerator):
    BASE_PATH = join(cons.AWS_LOGS, cons.RANDOM_ACCOUNT_ID, cons.ELASTIC_LOAD_BALANCING, cons.US_EAST_1_REGION)
    BASE_FILE_NAME = f"{cons.RANDOM_ACCOUNT_ID}_{cons.ELASTIC_LOAD_BALANCING}_{cons.US_EAST_1_REGION}_"

    def get_filename(self):
        """Return the filename in the NLB format.

        Example:
            <prefix>/AWSLogs/<suffix>/<organization_id>/<account_id>/elasticloadbalancing/<region>/<year>/<month>/<day>

        Returns:
            str: Synthetic filename.
        """
        now = datetime.utcnow()
        path = join(self.BASE_PATH, now.strftime(cons.PATH_DATE_FORMAT))
        name = (
            f"{self.BASE_FILE_NAME}net.qatests_{now.strftime(cons.FILENAME_DATE_FORMAT)}_{abs(hash(now))}_"
            f"{get_random_ip()}{cons.LOG_EXT}"
        )

        return join(path, name)

    def get_data_sample(self):
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
        csv.writer(buffer, delimiter=' ').writerows(data)

        return buffer.getvalue()


class KMSDataGenerator(DataGenerator):
    BASE_PATH = ''
    BASE_FILE_NAME = 'firehose_kms-1-'

    def get_filename(self):
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

    def get_data_sample(self):
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

    def get_filename(self):
        """Return the filename in the Macie format.

        Example:
            <prefix>/<year>/<month>/<day>

        Returns:
            str: Synthetic filename.
        """
        now = datetime.utcnow()
        path = join(self.BASE_PATH, now.strftime(cons.PATH_DATE_FORMAT))
        name = f"{self.BASE_FILE_NAME}{now.strftime(cons.FILENAME_DATE_FORMAT)}_{str(uuid4())}{cons.JSON_EXT}"

        return join(path, name)

    def get_data_sample(self):
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


class TrustedAdvisorDataGenerator(DataGenerator):
    BASE_PATH = ''
    BASE_FILE_NAME = 'firehose_trustedadvisor-1-'

    def get_filename(self):
        """Return the filename in the Trusted Advisor format.

        Example:
            <prefix>/<year>/<month>/<day>
        Returns:
            str: Synthetic filename.
        """
        now = datetime.utcnow()
        path = join(self.BASE_PATH, now.strftime(cons.PATH_DATE_FORMAT))
        name = f"{self.BASE_FILE_NAME}{now.strftime(cons.FILENAME_DATE_FORMAT)}{cons.JSON_EXT}"

        return join(path, name)

    def get_data_sample(self):
        """Return a sample of data according to the Trusted Advisor format.

        Returns:
            str: Synthetic data.
        """
        return json.dumps(
            {
                'version': '0',
                'id': get_random_string(26),
                'detail-type': 'Trusted Advisor Check Item Refresh Notification',
                'source': 'aws.trustedadvisor',
                'account': cons.RANDOM_ACCOUNT_ID,
                'time': datetime.utcnow().strftime(cons.FILENAME_DATE_FORMAT),
                'region': 'us-east-1',
                'resources': [],
                'detail': {
                    'check-name': 'IAM Group',
                    'check-item-detail': {
                        'Status': 'Green',
                        'Current Usage': '1',
                        'Limit Name': 'Groups',
                        'Region': '-',
                        'Service': 'IAM',
                        'Limit Amount': '300'
                    },
                    'status': 'OK',
                    'resource_id': '',
                    'uuid': str(uuid4())
                }
            }
        )


class GuardDutyDataGenerator(DataGenerator):
    BASE_PATH = ''
    BASE_FILE_NAME = 'firehose_guardduty-1-'

    def get_filename(self):
        """Return the filename in the Guard Duty format.

        Example:
            <prefix>/<year>/<month>/<day>
        Returns:
            str: Synthetic filename.
        """
        now = datetime.utcnow()
        path = join(self.BASE_PATH, now.strftime(cons.PATH_DATE_FORMAT))
        name = f"{self.BASE_FILE_NAME}{now.strftime(cons.FILENAME_DATE_FORMAT)}{cons.JSON_EXT}"

        return join(path, name)

    def get_data_sample(self):
        """Return a sample of data according to the Guard Duty format.

        Returns:
            str: Synthetic data.
        """
        return json.dumps(
            {
                'version': '0',
                'id': str(uuid4()),
                'detail-type': 'GuardDuty Finding',
                'source': 'aws.guardduty',
                'account': cons.RANDOM_ACCOUNT_ID,
                'time': '2021-07-08T03:45:04Z',
                'region': 'us-east-1',
                'resources': [],
                'detail': {
                    'schemaVersion': '2.0',
                    'accountId': cons.RANDOM_ACCOUNT_ID,
                    'region': 'us-east-1',
                    'partition': 'aws',
                    'id': 'e8bc77e2d65ffa20de95cc6e7a94e926',
                    'arn': f"arn:aws:guardduty:us-east-1:{cons.RANDOM_ACCOUNT_ID}:detector/",
                    'type': 'Recon:EC2/PortProbeUnprotectedPort',
                    'resource': {
                        'resourceType': 'Instance',
                        'instanceDetails': {
                            'instanceId': f"i-{get_random_string(8)}",
                            'instanceType': 't2.micro',
                            'launchTime': '2014-12-30T18:46:13Z',
                            'platform': None,
                            'productCodes': [],
                            'iamInstanceProfile': None,
                            'networkInterfaces': [
                                {
                                    'ipv6Addresses': [],
                                    'networkInterfaceId': f"eni-{get_random_string(8)}",
                                    'privateDnsName': 'ip-10-0-0-250.ec2.internal',
                                    'privateIpAddress': get_random_ip(),
                                    'privateIpAddresses': [
                                        {
                                            'privateDnsName': 'ip-10-0-0-250.ec2.internal',
                                            'privateIpAddress': get_random_ip()
                                        }
                                    ],
                                    'subnetId': 'subnet-6b1d6203',
                                    'vpcId': f"vpc-{get_random_string(8)}",
                                    'securityGroups': [
                                        {
                                            'groupName': 'default',
                                            'groupId': f"sg-{get_random_string(8)}"
                                        }
                                    ],
                                    'publicDnsName': 'ec2-105-71-92-143.compute-1.amazonaws.com',
                                    'publicIp': get_random_ip()
                                }
                            ],
                            'outpostArn': None,
                            'tags': [
                                {
                                    'key': 'service_name',
                                    'value': 'vpn'
                                },
                                {
                                    'key': 'Name',
                                    'value': 'vpn-gateway (r)'
                                }
                            ],
                            'instanceState': 'running',
                            'availabilityZone': 'us-east-1e',
                            'imageId': f"ami-{get_random_string(8)}",
                            'imageDescription': 'None'
                        }
                    },
                    'service': {
                        'serviceName': 'guardduty',
                        'detectorId': str(uuid4()),
                        'action': {
                            'actionType': 'PORT_PROBE',
                            'portProbeAction': {
                                'portProbeDetails': [
                                    {
                                        'localPortDetails': {
                                            'port': 1723,
                                            'portName': 'Unknown'
                                        },
                                        'remoteIpDetails': {
                                            'ipAddressV4': get_random_ip(),
                                            'organization': {
                                                'asn': '211680',
                                                'asnOrg': 'Sistemas Informaticos, S.A.',
                                                'isp': 'Sistemas Informaticos, S.A.',
                                                'org': 'Sistemas Informaticos, S.A.'
                                            },
                                            'country': {
                                                'countryName': 'Portugal'
                                            },
                                            'city': {
                                                'cityName': ''
                                            },
                                            'geoLocation': {
                                                'lat': 38.7057,
                                                'lon': -9.1359
                                            }
                                        }
                                    }
                                ],
                                'blocked': False
                            }
                        },
                        'resourceRole': 'TARGET',
                        'additionalInfo': {
                            'threatName': 'Scanner',
                            'threatListName': 'ProofPoint'
                        },
                        'evidence': {
                            'threatIntelligenceDetails': [
                                {
                                    'threatNames': [
                                        'Scanner'
                                    ],
                                    'threatListName': 'ProofPoint'
                                }
                            ]
                        },
                        'eventFirstSeen': '2021-04-20T14:40:04Z',
                        'eventLastSeen': '2021-07-08T03:15:41Z',
                        'archived': False,
                        'count': 5
                    },
                    'severity': 2,
                    'createdAt': '2021-04-20T14:53:32.735Z',
                    'updatedAt': '2021-07-08T03:31:04.017Z',
                    'title': 'Unprotected port on EC2 instance i-3bf6a5c5 is being probed.',
                    'description': (
                        'EC2 instance has an unprotected port which is being probed by a known malicious host.'
                        )
                }
            }
        )


class NativeGuardDutyDataGenerator(DataGenerator):
    BASE_PATH = join(cons.AWS_LOGS, cons.RANDOM_ACCOUNT_ID, cons.GUARDDUTY, cons.US_EAST_1_REGION)
    BASE_FILE_NAME = ''

    compress = True

    def get_filename(self):
        """Return the filename in the Native Guard Duty format.

        Example:
            <prefix>/AWSLogs/<suffix>/<account_id>/GuardDuty/<region>/<year>/<month>/<day>

        Returns:
            str: Synthetic filename.
        """
        now = datetime.utcnow()
        path = join(self.BASE_PATH, now.strftime(cons.PATH_DATE_FORMAT))
        name = f"{str(uuid4())}{cons.JSON_GZ_EXT}"

        return join(path, name)

    def get_data_sample(self):
        """Return a sample of data according to the Native Guard Duty format.

        Returns:
            str: Synthetic data.
        """
        random_ip = get_random_ip()
        return json.dumps(
            {
                'schemaVersion': '2.0',
                'accountId': cons.RANDOM_ACCOUNT_ID,
                'region': 'us-east-1',
                'partition': 'aws',
                'id': '3ac1fd234445e957d526a10c72631c8f',
                'arn': f"arn:aws:guardduty:us-east-1:{cons.RANDOM_ACCOUNT_ID}:detector/c0bfff53bb19fbee16ed05a0b21d3b/",
                'type': 'UnauthorizedAccess:EC2/SSHBruteForce',
                'resource': {
                    'resourceType': 'Instance',
                    'instanceDetails': {
                        'instanceId': f"i-{get_random_string(18)}",
                        'instanceType': 'c5.large',
                        'launchTime': '2022-10-19T16:17:42.000Z',
                        'platform': None,
                        'productCodes': [],
                        'iamInstanceProfile': None,
                        'networkInterfaces': [
                            {
                                'ipv6Addresses': [],
                                'networkInterfaceId': f"eni-{get_random_string(18)}",
                                'privateDnsName': f"ip-{random_ip.replace('.', '-')}.ec2.internal",
                                'privateIpAddress': random_ip,
                                'privateIpAddresses': [
                                    {
                                        'privateDnsName': f"ip-{random_ip.replace('.', '-')}.ec2.internal",
                                        'privateIpAddress': random_ip
                                    }
                                ],
                                'subnetId': f"subnet-{get_random_string(8)}",
                                'vpcId': 'vpc-f825c385',
                                'securityGroups': [
                                    {
                                        'groupName': 'test-ansible',
                                        'groupId': f"sg-{get_random_string(16)}"
                                    }
                                ],
                                'publicDnsName': f"ec2-{random_ip.replace('.', '-')}.compute-1.amazonaws.com",
                                'publicIp': random_ip
                            }
                        ],
                        'outpostArn': None,
                        'tags': [
                            {
                                'key': 'Name',
                                'value': 'some-test-server-investigating'
                            }
                        ],
                        'instanceState': 'running',
                        'availabilityZone': 'us-east-1d',
                        'imageId': 'ami-026b57f3c383c2eec',
                        'imageDescription': 'Amazon Linux 2 Kernel 5.10 AMI 2.0.20220912.1 x86_64 HVM gp2'
                    }
                },
                'service': {
                    'serviceName': 'guardduty',
                    'detectorId': 'c0bfff53bb19fbee16ed05a0b21d3be3',
                    'action': {
                        'actionType': 'NETWORK_CONNECTION',
                        'networkConnectionAction': {
                            'connectionDirection': 'INBOUND',
                            'remoteIpDetails': {
                                'ipAddressV4': random_ip,
                                'organization': {
                                    'asn': '3462',
                                    'asnOrg': 'Data Communication Business Group',
                                    'isp': 'Chunghwa Telecom',
                                    'org': 'Chunghwa Telecom'
                                },
                                'country': {
                                    'countryName': 'Taiwan'
                                },
                                'city': {
                                    'cityName': 'Tainan City'
                                },
                                'geoLocation': {
                                    'lat': 22.9917,
                                    'lon': 120.2148
                                }
                            },
                            'remotePortDetails': {
                                'port': get_random_port(),
                                'portName': 'Unknown'
                            },
                            'localPortDetails': {
                                'port': 22,
                                'portName': 'SSH'
                            },
                            'protocol': 'TCP',
                            'blocked': False,
                            'localIpDetails': {
                                'ipAddressV4': random_ip
                            }
                        }
                    },
                    'resourceRole': 'TARGET',
                    'additionalInfo': {
                        'value': '{}',
                        'type': 'default'
                    },
                    'eventFirstSeen': '2022-10-21T11:14:59.000Z',
                    'eventLastSeen': '2022-10-21T11:19:24.000Z',
                    'archived': False,
                    'count': 1
                },
                'severity': 2,
                'createdAt': '2022-10-21T11:21:10.027Z',
                'updatedAt': '2022-10-21T11:21:10.027Z',
                'title': f"{get_random_ip()} is performing SSH brute force attacks against i-08cb1e1f2bcce.",
                'description': f"{get_random_ip()} is performing SSH brute force attacks against i-08cb1ef2bcce.f"
            }
        ) + '\n'


class WAFDataGenerator(DataGenerator):
    BASE_PATH = ''
    BASE_FILE_NAME = 'aws-waf-logs-delivery-stream-1-'

    def get_filename(self):
        """Return the filename in the KMS format.

        Example:
            <prefix>/<year>/<month>/<day>
        Returns:
            str: Synthetic filename.
        """
        now = datetime.utcnow()
        path = join(self.BASE_PATH, now.strftime(cons.PATH_DATE_FORMAT))
        name = f"{self.BASE_FILE_NAME}{now.strftime(cons.FILENAME_DATE_FORMAT)}{cons.JSON_EXT}"

        return join(path, name)

    def get_data_sample(self):
        """Return a sample of data according to the cloudtrail format.

        Returns:
            str: Synthetic data.
        """
        return json.dumps(
            {
                'timestamp': 1576280412771,
                'formatVersion': 1,
                'webaclId': (
                    f"arn:aws:wafv2:ap-southeast-2:{cons.RANDOM_ACCOUNT_ID}:regional/"
                    'webacl/STMTest/1EXAMPLE-2ARN-3ARN-4ARN-123456EXAMPLE'
                ),
                'terminatingRuleId': 'STMTest_SQLi_XSS',
                'terminatingRuleType': 'REGULAR',
                'action': 'BLOCK',
                'terminatingRuleMatchDetails': [
                    {
                        'conditionType': 'SQL_INJECTION',
                        'sensitivityLevel': 'HIGH',
                        'location': 'HEADER',
                        'matchedData': [
                            '10',
                            'AND',
                            '1'
                        ]
                    }
                ],
                'httpSourceName': '-',
                'httpSourceId': '-',
                'ruleGroupList': [],
                'rateBasedRuleList': [],
                'nonTerminatingMatchingRules': [],
                'httpRequest': {
                    'clientIp': get_random_ip(),
                    'country': 'AU',
                    'headers': [
                        {
                            'name': 'Host',
                            'value': 'localhost:1989'
                        },
                        {
                            'name': 'User-Agent',
                            'value': 'curl/7.61.1'
                        },
                        {
                            'name': 'Accept',
                            'value': '*/*'
                        },
                        {
                            'name': 'x-stm-test',
                            'value': '10 AND 1=1'
                        }
                    ],
                    'uri': '/myUri',
                    'args': '',
                    'httpVersion': 'HTTP/1.1',
                    'httpMethod': 'GET',
                    'requestId': 'rid'
                },
                'labels': [
                    {
                        'name': 'value'
                    }
                ]
            }
        )


class ServerAccessDataGenerator(DataGenerator):
    BASE_PATH = ''
    BASE_FILE_NAME = ''

    def get_filename(self):
        """Return the filename in the server access format.

        Example:
            <prefix>/

        Returns:
            str: Synthetic filename.
        """
        now = datetime.utcnow()
        date_format = '%Y-%m-%d-%H-%M-%S'
        name = f"{now.strftime(date_format)}-{get_random_string(16).upper()}"
        return join(self.BASE_PATH, name)

    def get_data_sample(self):
        """Return a sample of data according to the server access format.

        Returns:
            str: Synthetic data.
        """
        data = []

        for _ in range(5):
            data.append(
                [
                    str(uuid4()), 'wazuh-server-access-integration-tests',
                    datetime.utcnow().strftime('[%d/%b/%Y:%H:%M:%S %z]'), get_random_ip(),
                    f"arn:aws:iam::{cons.RANDOM_ACCOUNT_ID}:user/fake.user", get_random_string(16).upper(),
                    'REST.GET.WEBSITE', '-', 'GET, /wazuh-server-access-integration-tests?website= HTTP/1.1',
                    '404', 'NoSuchWebsiteConfiguration', '343', '-', '85', '-', '-',
                    (
                        'S3Console/0.4, aws-internal/3 aws-sdk-java/1.11.991'
                        'Linux/4.9.230-0.1.ac.224.84.332.metal1.x86_64'
                        'OpenJDK_64-Bit_Server_VM/25.282-b08 java/1.8.0_282 vendor/Oracle_Corporation'
                        'cfg/retry-mode/legacy'
                    ),
                    '-', str(uuid4()), 'SigV4', 'ECDHE-RSA-AES128-GCM-SHA256', 'AuthHeader', 's3.amazonaws.com',
                    'TLSv1.2'

                ]
            )
        buffer = StringIO()
        csv.writer(buffer, delimiter=' ').writerows(data)

        return buffer.getvalue()


class UmbrellaDataGenerator(DataGenerator):
    BASE_PATH = 'dnslogs'
    BASE_FILE_NAME = ''

    def get_filename(self):
        """Return the filename in the umbrella format.

        Example:
            <prefix>/<year>-<month>-<day>
        Returns:
            str: Synthetic filename.
        """
        now = datetime.utcnow()
        path = join(self.BASE_PATH, now.strftime('%Y-%m-%d'))
        name = f"{self.BASE_FILE_NAME}{now.strftime('%Y-%m-%d')}-00-00-ioxa{cons.CSV_EXT}"

        return join(path, name)

    def get_data_sample(self):
        """Return a sample of data according to the cloudtrail format.

        Returns:
            str: Synthetic data.
        """
        data = []

        for _ in range(5):
            data.append(
                [
                    datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
                    'ActiveDirectoryUserName',
                    'ActiveDirectoryUserName,ADSite,Network',
                    get_random_ip(),
                    get_random_ip(),
                    'Allowed',
                    '1 (A)',
                    'NOERROR',
                    'domain-visited.com.',
                    'Chat,Photo Sharing,Social Networking,Allow List'
                ]
            )
        buffer = StringIO()
        csv.writer(buffer).writerows(data)

        return buffer.getvalue()


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
    cons.TRUSTED_ADVISOR_TYPE: TrustedAdvisorDataGenerator,
    cons.GUARD_DUTY_TYPE: GuardDutyDataGenerator,
    cons.NATIVE_GUARD_DUTY_TYPE: NativeGuardDutyDataGenerator,
    cons.WAF_TYPE: WAFDataGenerator,
    cons.SERVER_ACCESS: ServerAccessDataGenerator,
    cons.CISCO_UMBRELLA_TYPE: UmbrellaDataGenerator
}


def get_data_generator(bucket_type, bucket_name):
    """Given the bucket type return the correspondant data generator instance.

    Args:
        bucket_type (str): Bucket type to match the data generator.
        bucket_name (str): Bucket name to match in case of custom or guardduty types.

    Returns:
        DataGenerator: Data generator for the given bucket.
    """
    if bucket_type == cons.CUSTOM_TYPE:
        bucket_type = bucket_name.split('-')[1]
    elif bucket_type == cons.GUARD_DUTY_TYPE and 'native' in bucket_name:
        bucket_type = cons.NATIVE_GUARD_DUTY_TYPE

    return buckets_data_mapping[bucket_type]()
