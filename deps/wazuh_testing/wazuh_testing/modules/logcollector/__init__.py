import sys
from wazuh_testing.tools.monitoring import LOG_COLLECTOR_DETECTOR_PREFIX, AGENT_DETECTOR_PREFIX


# Variables
LOG_COLLECTOR_PREFIX = AGENT_DETECTOR_PREFIX if sys.platform == 'win32' else LOG_COLLECTOR_DETECTOR_PREFIX
WINDOWS_AGENT_PREFIX = r'.*wazuh-agent.*'
MAILD_PREFIX = r'.*wazuh-maild.*'


# Error Messages
GENERIC_CALLBACK_ERROR_COMMAND_MONITORING = 'The expected command monitoring log has not been produced'
ERR_MSG_UNEXPECTED_IGNORE_EVENT = "Found unexpected 'Ignoring the log <message> due to ignore/restrict config' event"


# Local_internal_options
if sys.platform == 'win32':
    LOGCOLLECTOR_DEFAULT_LOCAL_INTERNAL_OPTIONS = {
        'windows.debug': '2',
        'agent.debug': '2'
    }
else:
    LOGCOLLECTOR_DEFAULT_LOCAL_INTERNAL_OPTIONS = {
        'logcollector.debug': '2',
        'monitord.rotate_log': '0',
        'agent.debug': '0',
    }
