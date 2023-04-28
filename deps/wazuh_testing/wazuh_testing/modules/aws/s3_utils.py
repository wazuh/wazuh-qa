"""AWS S3 related utils"""

import gzip

import boto3
from botocore.exceptions import ClientError
from wazuh_testing import logger
from wazuh_testing.modules.aws.data_generator import get_data_generator

session = boto3.Session(profile_name='qa')
s3 = session.resource('s3')


def upload_file(bucket_type, bucket_name):
    """Upload a file to an S3 bucket.

    Args:
        bucket_type (str): Bucket type to generate the data.
        bucket_name (str): Bucket to upload.

    Returns:
        str: The name of the file if was uploaded, else ''.
    """
    dg = get_data_generator(bucket_type, bucket_name)
    filename = dg.get_filename()
    obj = s3.Object(bucket_name, filename)

    data = dg.get_data_sample().encode() if not dg.compress else gzip.compress(data=dg.get_data_sample().encode())

    # Upload the file
    try:
        obj.put(Body=data)
    except ClientError as e:
        logger.error(e)
        filename = ''
    return filename


def delete_file(filename, bucket_name):
    """Delete a given file from the bucket.

    Args:
        filename (str): Full filename to delete.
        bucket_name (str): Bucket that contains the file.
    """
    s3.Object(bucket_name, filename).delete()


def file_exists(filename, bucket_name):
    """Check if a file exists in a bucket.

    Args:
        filename (str): Full filename to check.
        bucket_name (str): Bucket that contains the file.
    Returns:
        bool: True if exists else False.
    """
    exists = True
    try:
        s3.Object(bucket_name, filename).load()
    except ClientError as error:
        if error.response['Error']['Code'] == '404':
            exists = False

    return exists


def get_last_file_key(bucket_type, bucket_name, execution_datetime):
    """Return the last file key contained in a default path of a bucket.

    Args:
        bucket_type (str): Bucket type to obtain the data generator.
        bucket_name (str): Bucket that contains the file.
        execution_datetime (datetime): Datetime to use to use as prefix.

    Returns:
        str: The last key in the bucket.
    """

    dg = get_data_generator(bucket_type, bucket_name)
    bucket = s3.Bucket(bucket_name)
    last_key = None

    try:
        *_, last_item = bucket.objects.filter(Prefix=dg.BASE_PATH or str(execution_datetime.year))
        last_key = last_item.key
    except ValueError:
        last_key = ''
    return last_key
