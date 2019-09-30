import subprocess
import shlex
import time
from datetime import timedelta
from _datetime import datetime

future = datetime.now() + timedelta(hours=13)
subprocess.call(shlex.split("timedatectl set-ntp false"))
subprocess.call(shlex.split("date -s '%s'" % future))
subprocess.call(shlex.split("hwclock -w"))
