# Description

This test suite aims to put to the test the Content Migration Tool with an end-to-end approach.

## Prerequisites

- Install Python 3
- Install Pip
- Install Content Migration tool (Follow [this guide](https://github.com/wazuh/wazuh-content#readme))

## Install the dependencies and QA Framework

Install the Python dependencies by running:

```
python3 -m pip install -U pip
python3 -m pip install -r requirements.txt --ignore-installed
```

Install the QA framework:

```
python3 -m pip install deps/wazuh_testing/.
```

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
