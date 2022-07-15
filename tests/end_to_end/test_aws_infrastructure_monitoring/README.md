## Description

The `test_aws_infrastructure_monitoring.py` module checks if alerts are triggered in the manager when an event obtained
from AWS services matches a rule.

## Global requirements

- Credentials (access key ID and secret access key) of an IAM User with permissions to:
  - Create S3 Buckets
  - Get data from S3 Buckets
  - Create and configure a Trail

### Use case: CloudTrail

**Preconditions**:
- Create and configure a Trail (you will create an S3 bucket in this process)
- Create an inventory as follows:
  ```
  all:
  hosts:
    wazuh-manager:
      ansible_connection: ssh
      ansible_user: USER
      ansible_password: PASSWORD
      ansible_ssh_private_key_file: PATH_TO_PRIVATE_KEY
      ansible_python_interpreter: /usr/bin/python
      dashboard_user: WAZUH_DASHBOARD_USER
      dashboard_password: WAZUH_DASHBOARD_PASS
  vars:
    bucket_name: S3_BUCKET_OF_THE_TRAIL
    aws_region: S3_BUCKET_REGION
    aws_access_key_id: IAM_USER_ACCESS_KEY_ID
    aws_secret_access_key: IAM_USER_SECRET_ACCESS_KEY
  ```

**How to run**: `python -m pytest -s tests/end_to_end/test_aws_infrastructure_monitoring/ --inventory_path <PATH_TO_INVENTORY>`
