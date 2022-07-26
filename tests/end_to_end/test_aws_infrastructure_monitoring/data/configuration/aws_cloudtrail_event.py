#!/usr/bin/python3

import argparse
from datetime import datetime, timedelta
from time import sleep
import boto3


# Hide deprecation warning for python<=3.6
boto3.compat.filter_python_deprecation_warnings()

formats = ['%a, %d %b %Y %H:%M:%S %Z', '%Y-%m-%dT%H:%M:%SZ']


def get_parameters():
    """
    Returns:
        argparse.Namespace: Object with the user parameters.
    """
    parser = argparse.ArgumentParser()

    parser.add_argument('--aws_access_key_id', '-a', type=str, action='store', required=True, dest='aws_access_key_id')
    parser.add_argument('--aws_secret_access_key', '-s', type=str, action='store', required=True,
                        dest='aws_secret_access_key')

    arguments = parser.parse_args()

    return arguments


def create_bucket(client):
    """Create an S3 bucket in the default region (us-east-1)

    Args:
        access_key_id (str): AWS access key ID
        secret_access_key (str): AWS secret access key
    """
    response = client.create_bucket(Bucket='delete-this-dummy-bucket')
    response_date = response['ResponseMetadata']['HTTPHeaders']['date']
    # The format of the request datetieme is changed here to match the timestamp of the AWS event in the alerts.json log
    # 1 second is substracted to avoid the difference with the server time
    request_datetime = datetime.strptime(response_date, formats[0]) - timedelta(seconds=1)
    datetime_str = request_datetime.strftime(formats[1])
    # Print the formatted time from the request because Ansible will pick it up from the standard output
    print(datetime_str)


def delete_bucket(client):
    """Delete an S3 bucket in the default region (us-east-1)

    Args:
        access_key_id (str): AWS access key ID
        secret_access_key (str): AWS secret access key
    """
    client.delete_bucket(Bucket='delete-this-dummy-bucket')


def main():
    parameters = get_parameters()
    client = boto3.client('s3', aws_access_key_id=parameters.aws_access_key_id,
                          aws_secret_access_key=parameters.aws_secret_access_key)
    create_bucket(client)
    # Wait for the event to be generated in AWS
    sleep(10)
    delete_bucket(client)


if __name__ == '__main__':
    main()
