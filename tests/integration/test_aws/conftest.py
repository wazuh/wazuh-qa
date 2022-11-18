import pytest
from wazuh_testing import logger
from wazuh_testing.modules.aws.s3_utils import delete_file, upload_file


@pytest.fixture(scope='function')
def upload_file_to_s3(metadata: dict) -> None:
    """Upload a file to S3 bucket

    Parameters
    ----------
    metadata : dict
        Metadata to get the parameters
    """
    bucket_name = metadata['bucket_name']
    uploaded, filename = upload_file(bucket_type=metadata['bucket_type'], bucket_name=bucket_name)
    logger.debug('Uploaded file: %s to bucket "%s"', filename, bucket_name)
    if uploaded:
        metadata["uploaded_file"] = filename


@pytest.fixture(scope='function')
def upload_and_delete_file_to_s3(metadata: dict):
    """Upload a file to S3 bucket and delete after the test ends.

    Parameters
    ----------
    metadata : dict
        Metadata to get the parameters
    """
    bucket_name = metadata['bucket_name']
    _, filename = upload_file(bucket_type=metadata['bucket_type'], bucket_name=metadata['bucket_name'])
    logger.debug('Uploaded file: %s to bucket "%s"', filename, bucket_name)

    yield

    delete_file(filename=filename, bucket_name=bucket_name)
    logger.debug('Deleted file: %s from bucket %s', filename, bucket_name)
