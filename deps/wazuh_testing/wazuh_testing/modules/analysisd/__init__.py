
ANALYSISD_PREFIX = r'.*wazuh-analysisd.*'
TESTRULE_PREFIX = r'.*wazuh-testrule.*'
MAILD_PREFIX = r'.*wazuh-maild.*'
QUEUE_EVENTS_SIZE = 16384
ANALYSISD_ONE_THREAD_CONFIG = {'analysisd.event_threads': '1', 'analysisd.syscheck_threads': '1',
                               'analysisd.syscollector_threads': '1', 'analysisd.rootcheck_threads': '1',
                               'analysisd.sca_threads': '1', 'analysisd.hostinfo_threads': '1',
                               'analysisd.winevt_threads': '1', 'analysisd.rule_matching_threads': '1',
                               'analysisd.dbsync_threads': '1', 'remoted.worker_pool': '1'}
# Callback Messages
CB_ANALYSISD_STARTUP_COMPLETED = fr"DEBUG: Startup completed. Waiting for new messages.*"

# Error messages
ERR_MSG_STARTUP_COMPLETED_NOT_FOUND = fr'Did not recieve the expected "{CB_ANALYSISD_STARTUP_COMPLETED}"'
