import http.server
import os
import socketserver
import threading
from functools import partial
from time import sleep

import pytest
from wazuh_testing.tools.file import remove_file, write_json_file
from wazuh_testing.tools.logging import Logging

logger = Logging('cmt')


@pytest.fixture(scope='session', autouse=True)
def setup_feed_server():
    """Setup an HTTP server that run in a daemon thread.
    """
    hostname = 'localhost'
    server_port = 8888
    server_directory = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data', 'input_data')
    handler = partial(http.server.SimpleHTTPRequestHandler, directory=server_directory)
    # Disable auto bind and activate
    httpd = socketserver.TCPServer((hostname, server_port), handler, False)
    # Allow reuse address to allow binding
    httpd.allow_reuse_address = True
    httpd.server_bind()
    httpd.server_activate()

    def _serve_forever(httpd):
        with httpd:
            logger.info(f"Serving at port {server_port}")
            httpd.serve_forever()

    # Start server on a separated thread
    # "(httpd, )" intentionally done to avoid module "threading" warning, due to expecting an iterable
    thread = threading.Thread(daemon=True, target=_serve_forever, args=(httpd, ))
    thread.start()
    # Wait for the server to fully initialize
    sleep(3)

    yield
    # After yield the server will stop abruptly because the main process will end


@pytest.fixture
def build_cmt_config_file(request, configuration):
    """Build the configuration file for the Content Migration Tool to run.
    """
    dest_path = os.path.join(request.module.configuration_path, 'config.json')
    write_json_file(file_path=dest_path, data=configuration)

    yield dest_path

    remove_file(dest_path)
