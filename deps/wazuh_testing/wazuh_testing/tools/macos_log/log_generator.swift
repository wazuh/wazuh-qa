import os.log

let log_parameters = CommandLine.arguments
let type_event = log_parameters[1]
let oslog_subsystem_category = OSLog(subsystem: log_parameters[2], category: log_parameters[3])

var oslog_type = OSLogType.default

switch type_event{
    case "info":
        oslog_type = OSLogType.info
    case "debug":
        oslog_type = OSLogType.debug
    case "default":
        oslog_type = OSLogType.default
    case "error":
        oslog_type = OSLogType.error
    case "fault":
        oslog_type = OSLogType.fault
    default:
        oslog_type = OSLogType.default
}

os_log("Custom os_log event message", log: oslog_subsystem_category, type: oslog_type)
