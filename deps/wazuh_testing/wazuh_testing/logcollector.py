from wazuh_testing.tools import monitoring


def callback_analyzing_file(file, prefix=monitoring.LOG_COLLECTOR_DETECTOR_PREFIX):
    msg = fr"Analyzing file: '{file}'."
    return monitoring.make_callback(pattern=msg, prefix=prefix, escape=True)


def callback_monitoring_command(log_format, command):
    log_format_message = 'full output' if log_format == 'full_command' else 'output'
    msg = fr"INFO: Monitoring {log_format_message} of command\(\d+\): {command}"
    return monitoring.make_callback(pattern=msg, prefix=monitoring.LOG_COLLECTOR_DETECTOR_PREFIX)


def callback_monitoring_djb_multilog(program_name, multilog_file):
    msg = fr"INFO: Using program name '{program_name}' for DJB multilog file: '{multilog_file}'."
    return monitoring.make_callback(pattern=msg, prefix=monitoring.LOG_COLLECTOR_DETECTOR_PREFIX)


def callback_command_alias_output(alias):
    msg = fr"Reading command message: 'ossec: output: '{alias}':"
    return monitoring.make_callback(pattern=msg, prefix=monitoring.LOG_COLLECTOR_DETECTOR_PREFIX)


def callback_query_bad_format(event_location):
    msg = fr"ERROR: Could not EvtSubscribe() for ({event_location}) which returned \(\d+\)"
    return monitoring.make_callback(pattern=msg, prefix=monitoring.LOG_COLLECTOR_DETECTOR_PREFIX)


def callback_socket_target(location, socket_name):
    msg = fr"DEBUG: Socket target for '{location}' -> {socket_name}"
    return monitoring.make_callback(pattern=msg, prefix=monitoring.LOG_COLLECTOR_DETECTOR_PREFIX)


def callback_socket_not_defined(location, socket_name):
    msg = fr"CRITICAL: Socket '{socket_name}' for '{location}' is not defined."
    return monitoring.make_callback(pattern=msg, prefix=monitoring.LOG_COLLECTOR_DETECTOR_PREFIX)


def callback_log_target_not_found(location, socket_name):
    msg = fr"WARNING: Log target '{socket_name}' not found for the output format of localfile '{location}'."
    return monitoring.make_callback(pattern=msg, prefix=monitoring.LOG_COLLECTOR_DETECTOR_PREFIX)


def callback_invalid_reconnection_time(severity='WARNING', default_value='5'):
    msg = fr"{severity}: Invalid reconnection time value. Changed to {default_value} seconds."
    return monitoring.make_callback(pattern=msg, prefix=monitoring.LOG_COLLECTOR_DETECTOR_PREFIX)
