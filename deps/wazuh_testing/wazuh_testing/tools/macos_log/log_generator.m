#import <os/activity.h>
#import <os/log.h>
#import <os/trace.h>

#define custom_os_log_message "Custom os_log event message"

int main(int argc, char ** argv){
    char *type = argv[1];
    char *level = argv[2];
    char *subsystem = argv[3];
    char *category = argv[4];

    if(strcmp(type, "activity") == 0){
        os_activity_initiate("Custom activity event message", OS_ACTIVITY_FLAG_DEFAULT, ^{});
    }
    else if(strcmp(type, "trace") == 0){
        os_trace("Custom trace event message");
    }
    else{
        os_log_t log = os_log_create(subsystem, category);
        if(strcmp(level, "info") == 0){
            os_log_info(log, custom_os_log_message);
        }
        else if(strcmp(level, "debug") == 0){
            os_log_debug(log, custom_os_log_message);
        }
        else if(strcmp(level, "error") == 0){
            os_log_error(log, custom_os_log_message);
        }
        else if(strcmp(level, "fault") == 0){
            os_log_fault(log, custom_os_log_message);
        }
        else{
            os_log(log, custom_os_log_message);
        }
    }
}
