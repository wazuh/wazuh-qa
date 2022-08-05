import os
import json
from datetime import datetime, timedelta
from copy import deepcopy

from wazuh_testing.tools.time import parse_date_time_format


# Timeouts
T_5 = 5
T_10 = 10
T_15 = 15
T_20 = 20
T_60 = 60

ANALYSISD_PREFIX = r'.*wazuh-analysisd*'
MAILD_PREFIX = r'.*wazuh-maild*'