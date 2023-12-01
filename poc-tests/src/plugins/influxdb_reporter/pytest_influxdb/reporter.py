import os
import logging
import warnings

from typing import Union
from datetime import datetime

import pytest

from _pytest.config import ExitCode, Config
from _pytest.main import Session
from _pytest.terminal import TerminalReporter
from _pytest.reports import TestReport
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS


log = logging.getLogger(__name__)


class InfluxDBReporter:
    def __init__(self, config: Config, config_file: str = None) -> None:
        self.config = config

        if config_file:
            # When the config file is specified, it has the priority
            self.client = InfluxDBClient.from_config_file(config_file)
            return

        # Get attributes from command line or environment variables
        if uri := config.getoption("--influxdb-url"):
            self.uri = uri
        else:
            self.uri = os.environ.get("INFLUXDB_URL")

        if token := config.getoption("--influxdb-token"):
            self.token = token
        else:
            self.token = os.environ.get("INFLUXDB_TOKEN")

        if bucket := config.getoption("--influxdb-bucket"):
            self.bucket = bucket
        else:
            self.bucket = os.environ.get("INFLUXDB_BUCKET")

        # Create client
        self.client = InfluxDBClient(url=self.uri, token=self.token)

    def report(self, session: Session) -> None:
        if not self.__validate_parameters():
            self.error = "Missing required connection parameters"
            return

        terminal_reporter = self. __get_terminal_reporter(session)
        # Special check for pytest-xdist plugin
        if hasattr(terminal_reporter.config, 'workerinput'):
            return

        points = self.__get_points(terminal_reporter.stats)
        self.__write_points(points)

    # --- Pytest hooks ---

    @pytest.hookimpl(trylast=True)
    def pytest_sessionfinish(self, session: Session, exitstatus: Union[int, ExitCode]) -> None:
        try:
            self.report(session)
        except Exception as e:
            self.error = f"InfluxDB report error: {self.uri} - {e}"
            log.error(self.error)

    @pytest.hookimpl(trylast=True)
    def pytest_terminal_summary(self, terminalreporter: TerminalReporter,
                                exitstatus: Union[int, ExitCode], config: Config) -> None:
        if self.error:
            terminalreporter.write_sep("-","Unable to send report to InfluxDB")
            terminalreporter.write(self.error)
            return
        terminalreporter.write_sep("-", "Report sent to InfluxDB successfully")

    # --- Private methods ---

    def __validate_parameters(self) -> bool:
        if None in [self.uri, self.bucket, self.token]:
            return False
        return True

    def __get_terminal_reporter(self, session: Session) -> TerminalReporter:
        plugin_manager = session.config.pluginmanager
        return plugin_manager.get_plugin("terminalreporter")

    def __get_points(self, report_stats: dict) -> list[Point]:
        points = []
        now = str(datetime.now())
        for _, value in report_stats.items():
            for test in value:
                data = self.__get_report_body(test, now)
                points.append(Point.from_dict(data))
        return points

    def __get_report_body(self, test_report: TestReport, datetime: str) -> dict:
        print(test_report.keywords)
        print(dir(test_report.keywords))
        fields = {
            'test_name': test_report.head_line,
            'date': datetime,
            'duration': test_report.duration,
            'result': test_report.outcome,
            'test_nodeid': test_report.nodeid,
            'test_part': test_report.when,
        }
        tags = {
            'test': test_report.fspath,
            'markers': test_report.keywords,
        }
        full_body = {
            'measurement': 'test_results',
            'tags': tags,
            'fields': fields
        }
        return full_body

    def __write_points(self, points: list[Point]) -> None:
        write_api = self.client.write_api(write_options=SYNCHRONOUS)
        write_api.write(bucket=self.bucket, record=points)
        write_api.close()
