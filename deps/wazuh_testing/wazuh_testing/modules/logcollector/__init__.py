import sys


LOG_COLLECTOR_PREFIX = r'.*wazuh-logcollector.*'
WINDOWS_AGENT_PREFIX = r'.*wazuh-agent.*'
MAILD_PREFIX = r'.*wazuh-maild.*'
GENERIC_CALLBACK_ERROR_COMMAND_MONITORING = 'The expected command monitoring log has not been produced'


# Error Messages
ERR_MSG_UNEXPECTED_IGNORE_EVENT = "Found unexpected 'Ignoring the log... due to ignore/restrict config' event"


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