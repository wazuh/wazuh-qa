
# Variables

# Callbacks
CB_VIRUSTOTAL_JSON_ALERT = r'.*VirusTotal: Alert - .*integration\":\"virustotal\".*'
CB_INVALID_JSON_ALERT_READ = r'.*wazuh-integratord.*WARNING: Invalid JSON alert read.*'
CB_OVERLONG_JSON_ALERT_READ = r'.*wazuh-integratord.*WARNING: Overlong JSON alert read.*'
CB_ALERTS_FILE_INODE_CHANGED = r'.*wazuh-integratord.*DEBUG: jqueue_next\(\): Alert file inode changed.*'

# Error messages
ERR_MSG_VIRUSTOTAL_ALERT_NOT_DETECTED = ''
ERR_MSG_INVALID_ALERT_NOT_FOUND =
ERR_MSG_OVERLONG_ALERT_NOT_FOUND =
ERR_MSG_ALERT_INODE_CHANGED_NOT_FOUND