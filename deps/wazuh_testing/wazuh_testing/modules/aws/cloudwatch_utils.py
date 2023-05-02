"""AWS CloudWatch related utils"""

from time import time
from uuid import uuid4

import boto3
from wazuh_testing.modules.aws import PERMANENT_CLOUDWATCH_LOG_GROUP, US_EAST_1_REGION

session = boto3.Session(profile_name='qa')
logs = session.client('logs', region_name=US_EAST_1_REGION)


def create_log_group(log_group_name):
    """Create a log group.

    Args:
        log_group_name (str): Log group name to create.
    """
    logs.create_log_group(logGroupName=log_group_name)


def delete_log_group(log_group_name):
    """Delete the given log group.

    Args:
        log_group_name (str): Log group name to delete.
    """
    logs.delete_log_group(logGroupName=log_group_name)


def create_log_stream(log_group=PERMANENT_CLOUDWATCH_LOG_GROUP):
    """Create a log stream within the given log group.

    Args:
        log_group (str, optional): Log group to store the stream. Defaults to PERMANENT_CLOUDWATCH_LOG_GROUP.

    Returns:
        str: The name of the created log stream.
    """
    log_stream_name = str(uuid4())
    logs.create_log_stream(logGroupName=log_group, logStreamName=log_stream_name)

    return log_stream_name


def delete_log_stream(log_stream, log_group=PERMANENT_CLOUDWATCH_LOG_GROUP):
    """Delete a log stream from the given log group.

    Args:
        log_stream (str): The log stream to delete.
        log_group (str, optional): Log group to delete the stream. Defaults to PERMANENT_CLOUDWATCH_LOG_GROUP.
    """
    logs.delete_log_stream(logGroupName=log_group, logStreamName=log_stream)


def create_log_events(log_stream, log_group=PERMANENT_CLOUDWATCH_LOG_GROUP, event_number=1):
    """Create a log event within the given log stream and group.

    Args:
        log_stream (str): The log stream to delete.
        log_group (str, optional): Log group to delete the stream. Defaults to PERMANENT_CLOUDWATCH_LOG_GROUP.
        event_number (int, optional): Number of events to create. Defaults to 1.
    """

    events = [
        {'timestamp': int(time() * 1000), 'message': f"Test event number {i}"} for i in range(event_number)
    ]

    logs.put_log_events(
        logGroupName=log_group, logStreamName=log_stream, logEvents=events,
    )


def log_stream_exists(log_group, log_stream) -> bool:
    """Check if a log stream exists in a group.

    Args:
        log_group (str): Log group to search within.
        log_stream (str): Log stream to search.

    Returns:
        bool: True if exists else False
    """
    response = logs.describe_log_streams(logGroupName=log_group)
    log_streams = [item['logStreamName'] for item in response['logStreams']]

    return log_stream in log_streams
