#!/usr/bin/python3

import argparse
import boto3


# Hide deprecation warning for python<=3.6
boto3.compat.filter_python_deprecation_warnings()


def get_parameters():
    """
    Returns:
        argparse.Namespace: Object with the user parameters.
    """
    parser = argparse.ArgumentParser()

    parser.add_argument('--aws_access_key_id', '-i', type=str, action='store', required=True)
    parser.add_argument('--aws_secret_access_key', '-k', type=str, action='store', required=True)
    parser.add_argument('--bucket_name', '-b', type=str, action='store', required=True)
    parser.add_argument('--create', '-c', action='store_true')

    arguments = parser.parse_args()

    return arguments


def main():
    parameters = get_parameters()

    client = boto3.client('s3', aws_access_key_id=parameters.aws_access_key_id,
                          aws_secret_access_key=parameters.aws_secret_access_key)

    if parameters.create:
        client.create_bucket(Bucket=parameters.bucket_name)
    else:
        client.delete_bucket(Bucket=parameters.bucket_name)


if __name__ == '__main__':
    main()
