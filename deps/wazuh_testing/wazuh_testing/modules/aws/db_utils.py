import sqlite3
from collections import namedtuple
from pathlib import Path
from typing import Iterator

from .constants import S3_CLOUDTRAIL_DB_PATH

SELECT_QUERY_TEMPLATE = "SELECT * FROM {table_name}"

S3CloudTrailRow = namedtuple(
    'S3CloudTrailRow', 'bucket_path aws_account_id aws_region log_key processed_date created_date'
)


def get_db_connection(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(path)

# cloudtrail.db utils


def s3_db_exists() -> bool:
    """Check if `s3_cloudtrail.db` exists"""
    return S3_CLOUDTRAIL_DB_PATH.exists()


def delete_s3_db() -> None:
    """Delete `s3_cloudtrail.db` file"""
    if s3_db_exists():
        S3_CLOUDTRAIL_DB_PATH.unlink()


def get_s3_db_row(table_name: str) -> S3CloudTrailRow:
    connection = get_db_connection(S3_CLOUDTRAIL_DB_PATH)
    cursor = connection.cursor()
    result = cursor.execute(SELECT_QUERY_TEMPLATE.format(table_name=table_name)).fetchone()

    return S3CloudTrailRow(*result)


def get_multiple_s3_db_row(table_name: str) -> Iterator[S3CloudTrailRow]:
    connection = get_db_connection(S3_CLOUDTRAIL_DB_PATH)
    cursor = connection.cursor()

    for row in cursor.execute(SELECT_QUERY_TEMPLATE.format(table_name=table_name)):
        yield S3CloudTrailRow(*row)


def table_exists(table_name: str) -> bool:
    connection = get_db_connection(S3_CLOUDTRAIL_DB_PATH)
    cursor = connection.cursor()
    query = """
        SELECT
            name
        FROM
            sqlite_schema
        WHERE
            type ='table' AND
            name NOT LIKE 'sqlite_%';
    """

    return table_name in cursor.execute(query).fetchone()
