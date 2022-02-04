# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import sys
sys.path.append('/wazuh-qa/deps/wazuh_testing')
from wazuh_testing import wazuh_db

result = wazuh_db.query_wdb(sys.argv[1])
if result:
  print(result)
