

# Timeouts
T_5 = 5
T_10 = 10
T_15 = 15
T_20 = 20
T_60 = 60
T_40 = 40


# Variables
SCA_PREFIX = '.*sca.*'


# Callback Messages
CB_SCA_STARTED = f"{SCA_PREFIX}INFO: Module started."
CB_SCA_DISABLED = f"{SCA_PREFIX}INFO: Module disabled. Exiting."
CB_SCA_SCAN_STARTED = f"{SCA_PREFIX}INFO: Starting Security Configuration Assessment scan."
CB_SCA_SCAN_ENDED = f"{SCA_PREFIX}INFO: Security Configuration Assessment scan finished. Duration: (\d+) seconds."
CB_POLICY_EVALUATION_FINISHED = f"{SCA_PREFIX}INFO: Evaluation finished for policy '(.*)'."
CB_SCAN_DB_DUMP_FINISHED = f".*sca.*DEBUG: Finished dumping scan results to SCA DB for policy '(.*)'.*"


# Error Messages


# Setting Local_internal_option file
SCA_DEFAULT_LOCAL_INTERNAL_OPTIONS = {'wazuh_modules.debug': '2'}