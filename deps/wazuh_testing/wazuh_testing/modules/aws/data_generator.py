"""Utils to generate sample data to AWS"""
from datetime import datetime
from uuid import uuid4
from typing import Optional

from . import constants as cons


class DataGenerator:
    BASE_PATH = ''
    BASE_FILE_NAME = ''

    def get_filename(self, *args, **kwargs) -> str:
        """Returns the filename according to the integration format.

        Returns:
            str: Syntetic filename.
        """
        raise NotImplementedError()

    def get_data_sample(self, *args, **kwargs) -> dict:
        """Returns a sample of data according to the integration format.

        Returns:
            dict: Syntetic data.
        """
        raise NotImplementedError()


class CloudTrailDataGenerator(DataGenerator):
    BASE_PATH = f'{cons.AWS_LOGS}/{cons.RANDOM_ACCOUNT_ID}/{cons.CLOUD_TRAIL}/{cons.US_EAST_1_REGION}/'
    BASE_FILE_NAME = f'{cons.RANDOM_ACCOUNT_ID}_{cons.CLOUD_TRAIL}_{cons.US_EAST_1_REGION}_'

    def get_filename(self, *args, **kwargs) -> str:
        """Return the filename in the cloudtrail format.

        Example:
            <prefix>/AWSLogs/<suffix>/<organization_id>/<account_id>/CloudTrail/<region>/<year>/<month>/<day>

        Returns:
            str: Syntetic filename.
        """
        now = datetime.now()
        path = f"{self.BASE_PATH}{now.strftime(cons.PATH_DATE_FORMAT)}/"
        name = f"{self.BASE_FILE_NAME}{now.strftime(cons.FILENAME_DATE_FORMAT)}_{abs(hash(now))}{cons.JSON_EXT}"

        return f'{path}{name}'

    def get_data_sample(self) -> dict:
        """Returns a sample of data according to the cloudtrail format.

        Returns:
            dict: Syntetic data.
        """
        return {
            'Records': [
                {
                    'eventVersion': '1.08',
                    'userIdentity': {
                        'type': 'AWSService',
                        'invokedBy': 'ec2.amazonaws.com'
                    },
                    'eventTime': datetime.now().strftime(cons.EVENT_TIME_FORMAT),
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
        }


# Maps bucket type with corresponding data generator
buckets_data_mapping = {
    cons.CLOUD_TRAIL_TYPE: CloudTrailDataGenerator
}


def get_data_generator(bucket_type: str) -> DataGenerator:
    """Given the bucket type return the correspondant data generator instance.

    Args:
        bucket_type (str): Bucket type to match the data generator.

    Returns:
        DataGenerator: Data generator for the given bucket.
    """
    return buckets_data_mapping[bucket_type]()
