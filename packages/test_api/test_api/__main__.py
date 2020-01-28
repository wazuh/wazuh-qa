# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging
import os

import connexion

from test_api import __path__ as api_path


def main():
    logger = logging.getLogger('test_api')
    logger.addHandler(logging.FileHandler(os.path.join(os.getcwd(), 'test_api.log')))
    logger.setLevel(logging.INFO)

    app = connexion.App(__name__, specification_dir=os.path.join(api_path[0], 'spec'))
    app.add_api('spec.yaml', arguments={'title': 'Wazuh API'}, strict_validation=True, validate_responses=True)
    app.app.logger = logger

    app.run(host='0.0.0.0', port=56000)


if __name__ == "__main__":
    # execute only if run as a script
    main()
