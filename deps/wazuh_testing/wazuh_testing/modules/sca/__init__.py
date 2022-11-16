# Copyright (C) 2015-2022, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh_testing import MODULESD_DEBUG, VERBOSE_DEBUG_OUTPUT

# Variables
TEMP_FILE_PATH = '/tmp'


# Callback Messages
CB_SCA_ENABLED = r".*sca.*INFO: (Module started.)"
CB_SCA_DISABLED = r".*sca.*INFO: (Module disabled). Exiting."
CB_SCA_SCAN_STARTED = r".*sca.*INFO: (Starting Security Configuration Assessment scan)."
CB_SCA_SCAN_ENDED = r".*sca.*INFO: Security Configuration Assessment scan finished. Duration: (\d+) seconds."
CB_SCA_OSREGEX_ENGINE = r".*sca.*DEBUG: SCA will use '(.*)' engine to check the rules."
CB_POLICY_EVALUATION_FINISHED = r".*sca.*INFO: Evaluation finished for policy '(.*)'."
CB_SCAN_DB_DUMP_FINISHED = r".*sca.*DEBUG: Finished dumping scan results to SCA DB for policy '(.*)'.*"
CB_SCAN_RULE_RESULT = r".*sca.*wm_sca_hash_integrity.*DEBUG: ID: (\d+); Result: '(.*)'"
CB_SCA_SCAN_EVENT = r".*sca_send_alert.*Sending event: (.*)"


# Error Messages
ERR_MSG_REGEX_ENGINE = "Did not receive the expected 'SCA will use '.*' engine to check the rules' event"
ERR_MSG_ID_RESULTS = 'Expected sca_has_integrity result events not found'
ERR_MSG_SCA_SUMMARY = 'Expected SCA Scan Summary type event not found.'

# Setting Local_internal_option file
SCA_DEFAULT_LOCAL_INTERNAL_OPTIONS = {MODULESD_DEBUG: VERBOSE_DEBUG_OUTPUT}
