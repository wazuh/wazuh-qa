#!/usr/local/bin/python3.8

import argparse
import logging
import boto3
from botocore.exceptions import ClientError


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
    try:
        client = boto3.client('s3', aws_access_key_id=access_key_id,
                            aws_secret_access_key=secret_access_key)
        client.create_bucket(Bucket='delete-this-dummy-bucket')
    except ClientError as e:
        logging.error(e)


def main():
    parameters = get_parameters()
    create_bucket(parameters.aws_access_key_id, parameters.aws_secret_access_key)


if __name__ == '__main__':
    main()