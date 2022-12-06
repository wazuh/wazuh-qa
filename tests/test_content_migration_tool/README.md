# Description

This test suite aims to put to the test the Content Migration Tool with an end-to-end approach.

# Requirements to run the tests

## Install the following packages/tools:
- Python 3.10
- Pip
- Content Migration tool (Follow [this guide](https://github.com/wazuh/wazuh-content#readme))

## Install the dependencies

Install the Python dependencies by running: `python3 -m pip install -r tests/test_content_migration_tool/requirements.txt`

## Install the server

### Ubuntu

```
apt-get update -y && \
apt-get install -y mysql-server && \
service mysql start && service mysql status
```

### CentOS

```
yum update -y && \
rpm -ivh https://dev.mysql.com/get/mysql80-community-release-el8-4.noarch.rpm && \
yum install -y mysql-server && \
systemctl start mysqld && systemctl status mysqld
```

## Create a testing user and database

```
mysql -u root <<MYSQL_SCRIPT
CREATE DATABASE IF NOT EXISTS test_database;
CREATE USER IF NOT EXISTS 'test'@'localhost' IDENTIFIED BY 'Test123$';
GRANT ALL PRIVILEGES ON test_database.* TO 'test'@'localhost';
FLUSH PRIVILEGES;
quit
MYSQL_SCRIPT
```
