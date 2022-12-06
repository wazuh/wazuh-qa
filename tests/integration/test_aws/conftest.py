from typing import Generator

import pytest
from wazuh_testing import UDP, logger
from wazuh_testing.modules.aws.db_utils import delete_s3_db
from wazuh_testing.modules.aws.s3_utils import delete_file, upload_file
from wazuh_testing.tools import ANALYSISD_QUEUE_SOCKET_PATH, LOG_FILE_PATH
from wazuh_testing.tools.file import bind_unix_socket
from wazuh_testing.tools.monitoring import FileMonitor, ManInTheMiddle, QueueMonitor
from wazuh_testing.tools.services import control_service


@pytest.fixture(scope="function")
def wazuh_log_monitor() -> FileMonitor:
    return FileMonitor(LOG_FILE_PATH)


@pytest.fixture(scope="function")
def analysisd_monitor() -> Generator:
    def intercept_socket_data(data):
        return data

    control_service('stop', daemon='wazuh-analysisd')
    bind_unix_socket(ANALYSISD_QUEUE_SOCKET_PATH, UDP)

    mitm = ManInTheMiddle(
        address=ANALYSISD_QUEUE_SOCKET_PATH, family='AF_UNIX', connection_protocol=UDP, func=intercept_socket_data
    )
    mitm.start()

    yield QueueMonitor(mitm.queue)

    mitm.shutdown()
    control_service('start', daemon='wazuh-analysisd')


# S3 fixtures

@pytest.fixture(scope='function')
def upload_file_to_s3(metadata: dict) -> None:
    """Upload a file to S3 bucket

    Parameters
    ----------
    metadata : dict
        Metadata to get the parameters
    """
    bucket_name = metadata['bucket_name']
    filename = upload_file(bucket_type=metadata['bucket_type'], bucket_name=bucket_name)
    if filename != '':
        logger.debug('Uploaded file: %s to bucket "%s"', filename, bucket_name)
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
    filename = upload_file(bucket_type=metadata['bucket_type'], bucket_name=metadata['bucket_name'])
    if filename != '':
        logger.debug('Uploaded file: %s to bucket "%s"', filename, bucket_name)
        metadata["uploaded_file"] = filename

    yield

    delete_file(filename=filename, bucket_name=bucket_name)
    logger.debug('Deleted file: %s from bucket %s', filename, bucket_name)

# DB fixtures

@pytest.fixture(scope='function')
def clean_s3_cloudtrail_db():
    """Delete the DB file before and after the test execution"""
    delete_s3_db()

    yield

    delete_s3_db()
