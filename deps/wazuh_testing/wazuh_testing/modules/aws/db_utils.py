import sqlite3
from collections import namedtuple
from pathlib import Path
from typing import Iterator, Type

from .constants import (
    ALB_TYPE,
    CLB_TYPE,
    CLOUD_TRAIL_TYPE,
    CUSTOM_TYPE,
    GUARD_DUTY_TYPE,
    NLB_TYPE,
    S3_CLOUDTRAIL_DB_PATH,
    VPC_FLOW_TYPE,
    WAF_TYPE,
    SERVER_ACCESS_TABLE_NAME,
    AWS_SERVICES_DB_PATH
)

SELECT_QUERY_TEMPLATE = 'SELECT * FROM {table_name}'

S3CloudTrailRow = namedtuple(
    'S3CloudTrailRow', 'bucket_path aws_account_id aws_region log_key processed_date created_date'
)

S3VPCFlowRow = namedtuple(
    'S3VPCFlowRow', 'bucket_path aws_account_id aws_region flowlog_id log_key processed_date created_date'
)

S3ALBRow = namedtuple(
    'S3ALBRow', 'bucket_path aws_account_id log_key processed_date created_date'
)

S3CustomRow = namedtuple(
    'S3CustomRow', 'bucket_path aws_account_id log_key processed_date created_date'
)

S3GuardDutyRow = namedtuple(
    'S3GuardDutyRow', 'bucket_path aws_account_id log_key processed_date created_date'
)

S3WAFRow = namedtuple(
    'S3WAFRow', 'bucket_path aws_account_id log_key processed_date created_date'
)

S3ServerAccessRow = namedtuple(
    'S3ServerAccessRow', 'bucket_path aws_account_id log_key processed_date created_date'
)

ServiceInspectorRow = namedtuple(
    'ServiceInspectorRow', 'service account_id region timestamp'
)

ServiceCloudWatchRow = namedtuple(
    'ServiceCloudWatchRow', 'aws_region aws_log_group aws_log_stream next_token start_time end_time'
)

s3_rows_map = {
    CLOUD_TRAIL_TYPE: S3CloudTrailRow,
    VPC_FLOW_TYPE: S3VPCFlowRow,
    ALB_TYPE: S3ALBRow,
    CLB_TYPE: S3ALBRow,
    NLB_TYPE: S3ALBRow,
    CUSTOM_TYPE: S3CustomRow,
    GUARD_DUTY_TYPE: S3GuardDutyRow,
    WAF_TYPE: S3WAFRow,
    SERVER_ACCESS_TABLE_NAME: S3ServerAccessRow
}

service_rows_map = {
    'cloudwatch_logs': ServiceCloudWatchRow,
    'aws_services': ServiceInspectorRow

}


def _get_s3_row_type(bucket_type: str) -> Type[S3CloudTrailRow]:
    return s3_rows_map.get(bucket_type, S3CloudTrailRow)


def _get_service_row_type(table_name: str) -> Type[ServiceCloudWatchRow]:
    return service_rows_map.get(table_name, ServiceCloudWatchRow)


def get_db_connection(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(path)


def table_exists(table_name: str, db_path: Path = S3_CLOUDTRAIL_DB_PATH) -> bool:
    """Check if the given table name exists.

    Args:
        table_name (str): Table name to search for.

    Returns:
        bool: True if exists else False.
    """
    connection = get_db_connection(db_path)
    cursor = connection.cursor()
    query = """
        SELECT
            name
        FROM
            sqlite_master
        WHERE
            type ='table' AND
            name NOT LIKE 'sqlite_%';
    """

    return table_name in [result[0] for result in cursor.execute(query).fetchall()]


# cloudtrail.db utils


def s3_db_exists() -> bool:
    """Check if `s3_cloudtrail.db` exists.

    Returns:
        bool: True if exists else False.
    """
    return S3_CLOUDTRAIL_DB_PATH.exists()


def delete_s3_db() -> None:
    """Delete `s3_cloudtrail.db` file."""
    if s3_db_exists():
        S3_CLOUDTRAIL_DB_PATH.unlink()


def get_s3_db_row(table_name: str) -> S3CloudTrailRow:
    """Return one row from the given table name.

    Args:
        table_name (str): Table name to search into.

    Returns:
        S3CloudTrailRow: The first row of the table.
    """
    connection = get_db_connection(S3_CLOUDTRAIL_DB_PATH)
    cursor = connection.cursor()
    result = cursor.execute(SELECT_QUERY_TEMPLATE.format(table_name=table_name)).fetchone()
    row_type = _get_s3_row_type(table_name)

    return row_type(*result)


def get_multiple_s3_db_row(table_name: str) -> Iterator[S3CloudTrailRow]:
    """Return all rows from the given table name.

    Args:
        table_name (str): Table name to search into.

    Yields:
        Iterator[S3CloudTrailRow]: All the rows in the table.
    """
    connection = get_db_connection(S3_CLOUDTRAIL_DB_PATH)
    cursor = connection.cursor()
    row_type = _get_s3_row_type(table_name)

    for row in cursor.execute(SELECT_QUERY_TEMPLATE.format(table_name=table_name)):
        yield row_type(*row)


def table_exists_or_has_values(table_name: str, db_path: Path = S3_CLOUDTRAIL_DB_PATH) -> bool:
    """Check if the given table name exists. If exists check if has values.

    Args:
        table_name (str): Table name to search for.

    Returns:
        bool: True if exists or has values else False.
    """
    connection = get_db_connection(db_path)
    cursor = connection.cursor()
    try:
        return bool(cursor.execute(SELECT_QUERY_TEMPLATE.format(table_name=table_name)).fetchall())
    except sqlite3.OperationalError:
        return False


# aws_services.db utils

def services_db_exists() -> bool:
    """Check if `aws_services.db` exists.

    Returns:
        bool: True if exists else False.
    """
    return AWS_SERVICES_DB_PATH.exists()


def delete_services_db() -> None:
    """Delete `aws_services.db` file."""
    if services_db_exists():
        AWS_SERVICES_DB_PATH.unlink()


def get_service_db_row(table_name: str) -> ServiceCloudWatchRow:
    """Return one row from the given table name.

    Args:
        table_name (str): Table name to search into.

    Returns:
        ServiceInspectorRow: The first row of the table.
    """
    row_type = _get_service_row_type(table_name)
    connection = get_db_connection(AWS_SERVICES_DB_PATH)
    cursor = connection.cursor()
    result = cursor.execute(SELECT_QUERY_TEMPLATE.format(table_name=table_name)).fetchone()

    return row_type(*result)


def get_multiple_service_db_row(table_name: str) -> Iterator[ServiceCloudWatchRow]:
    """Return all rows from the given table name.

    Args:
        table_name (str): Table name to search into.

    Yields:
        Iterator[ServiceInspectorRow]: All the rows in the table.
    """
    row_type = _get_service_row_type(table_name)
    connection = get_db_connection(AWS_SERVICES_DB_PATH)
    cursor = connection.cursor()

    for row in cursor.execute(SELECT_QUERY_TEMPLATE.format(table_name=table_name)):
        yield row_type(*row)
