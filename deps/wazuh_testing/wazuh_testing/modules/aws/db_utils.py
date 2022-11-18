from .constants import S3_CLOUDTRAIL_DB_PATH

def delete_s3_db() -> None:
    """Delete `s3_cloudtrail.db` file"""
    if S3_CLOUDTRAIL_DB_PATH.exists():
        S3_CLOUDTRAIL_DB_PATH.unlink()
