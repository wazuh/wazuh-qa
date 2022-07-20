#!/usr/bin/python3

import argparse
from datetime import datetime
import boto3


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


def create_bucket(access_key_id, secret_access_key):
    """ Create an S3 bucket in the default region (us-east-1)

    Args:
        access_key_id (str): AWS access key ID
        secret_access_key (str): AWS secret access key
    """
    client = boto3.client('s3', aws_access_key_id=access_key_id, aws_secret_access_key=secret_access_key)
    response = client.create_bucket(Bucket='delete-this-dummy-bucket')
    response_date = response['ResponseMetadata']['HTTPHeaders']['date']
    # The format of the request datetieme is changed here to match the timestamp of the AWS event in the alerts.json log
    request_datetime = datetime.strptime(response_date, formats[0])
    # The last 3 characters are removed due to the difference with the server in seconds.
    # e.g: 2022-07-20T15:41:05Z --> 2022-07-20T15:41:
    datetime_str = request_datetime.strftime(formats[1])[:-3]
    # Print the formatted time from the request because Ansible will pick it up from the standard output
    print(datetime_str)


def main():
    parameters = get_parameters()
    create_bucket(parameters.aws_access_key_id, parameters.aws_secret_access_key)


if __name__ == '__main__':
    main()
