import logging

# The logging module will use the generic logger anyway
# that is because the logging module is a singleton.
# So, we can just use it this way here, and it will work.
logger = (lambda: logging.getLogger("workflow_engine"))()
