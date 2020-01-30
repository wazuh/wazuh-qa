# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import connexion
import logging

logger = logging.getLogger('test_api')


def execute_code():
    """
    POST /execute controller

    Run the body of the request as Python script
    """
    try:
        if connexion.request.is_json:
            lines = connexion.request.get_json()['lines']
            script = ';'.join(lines)
            exec(script)
        else:
            return connexion.problem(400, 'Bad request', 'Body request does not fit spec')
    except Exception as e:
        logger.error(f"Exception: {e}", exc_info=True)
        return connexion.problem(500, 'Error executing script', f'Error: {e}')

    return 'OK', 200
