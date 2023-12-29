import os
import logging

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
    """
    A class used to report test results to InfluxDB.

    Attributes:
        config (pytest.Config): The pytest configuration object.
        client (InfluxDBClient): The InfluxDB client.
        uri (str): The URI of the InfluxDB server.
        token (str): The token to authenticate with the InfluxDB server.
        bucket (str): The bucket to write data to.
        org (str): The organization to write data to.
        error (str): Any error that occurred while reporting.
    """

    def __init__(self, config: Config, config_file: str = None) -> None:
        """
        Constructs all the necessary attributes for the InfluxDBReporter object.

        Args:
            config (pytest.Config): Pytest configuration object.
            config_file (str | None): Path to the InfluxDB configuration file (default is None).
        """
        self.error: str = None

        if config_file:
            # When the config file is specified, it has the priority
            self.client = InfluxDBClient.from_config_file(config_file)
            return

        # Get attributes from command line or environment variables
        self.uri: str = config.getoption('--influxdb-url') \
                        or os.environ.get('INFLUXDB_URL')
        self.token: str = config.getoption('--influxdb-token') \
                          or os.environ.get('INFLUXDB_TOKEN')
        self.bucket: str = config.getoption('--influxdb-bucket') \
                           or os.environ.get('INFLUXDB_BUCKET')
        self.org: str = config.getoption('--influxdb-org') \
                        or os.environ.get('INFLUXDB_ORG')

        # Create client
        self.client = InfluxDBClient(self.uri, self.token, org=self.org)

    def report(self, session: Session) -> None:
        """
        Reports the test results to InfluxDB.

        Args:
            session (pytest.Session): The pytest session object.
        """
        if not self.__validate_parameters():
            self.error = 'Missing required connection parameters'
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
        """
        Pytest hook that is called when the test session finishes.

        Args:
            session (pytest.Session): The pytest session object.
            exitstatus (int | ExitCode): The exit status of the test session.
        """
        try:
            self.report(session)
        except Exception as e:
            self.error = f'InfluxDB report error: {self.uri} - {e}'
            log.error(self.error)

    @pytest.hookimpl(trylast=True)
    def pytest_terminal_summary(self, terminalreporter: TerminalReporter,
                                exitstatus: Union[int, ExitCode], config: Config) -> None:
        """
        Pytest hook that is called to add an additional section in the terminal summary reporting.

        Args:
            terminalreporter (pytest.TerminalReporter): The terminal reporter object.
            exitstatus (int | ExitCode): The exit status of the test session.
            config (Config): The pytest configuration object.
        """
        if self.error:
            terminalreporter.write_sep('-', 'Unable to send report to InfluxDB')
            terminalreporter.write(f'\n{self.error}\n')
            return
        terminalreporter.write_sep('-', 'Report sent to InfluxDB successfully')

    # --- Private methods ---

    def __validate_parameters(self) -> bool:
        """
        Validates the connection parameters.

        Returns:
            bool: True if the connection parameters are valid, False otherwise.
        """
        if None in [self.uri, self.bucket, self.token]:
            return False
        return True

    def __get_terminal_reporter(self, session: Session) -> TerminalReporter:
        """
        Gets the terminal reporter plugin.

        Args:
            session (pytest.Session): The pytest session object.

        Returns:
            pytest.TerminalReporter: The terminal reporter plugin.
        """
        plugin_manager = session.config.pluginmanager
        return plugin_manager.get_plugin('terminalreporter')

    def __get_points(self, report_stats: dict) -> list[Point]:
        """
        Gets the points to write to InfluxDB.

        Args:
            report_stats (dict): The report statistics.

        Returns:
            list[Point]: The points to write to InfluxDB.
        """
        points = []
        now = str(datetime.now())
        for _, report_items in report_stats.items():
            for report in report_items:
                if type(report) is not TestReport:
                    continue
                data = self.__get_report_body(report, now)
                points.append(Point.from_dict(data))
        return points

    def __get_report_body(self, test_report: TestReport, datetime: str) -> dict:
        """
        Gets the body of the report.

        Args:
            test_report (pytest.TestReport): The test report object.
            datetime (str): The date and time of the report.

        Returns:
            dict: The body of the report.
        """
        fields = {
            'test_name': test_report.head_line,
            'node_id': test_report.nodeid,
            'date': datetime,
            'duration': test_report.duration,
            'result': test_report.outcome,
            'stage': test_report.when,
        }
        tags = {
            'test': test_report.fspath,
            'markers': self.__get_pytest_marks(test_report.keywords),
            'when': test_report.when,
        }
        full_body = {
            'measurement': 'test_results',
            'tags': tags,
            'fields': fields
        }
        return full_body

    def __get_pytest_marks(self, keywords: dict) -> list[str]:
        """
        Extracts pytest marks from the given keywords.

        Args:
            keywords (dict): The keywords dictionary.

        Returns:
            list[str]: A list of pytest marks.
        """
        marks = []
        for key, _ in keywords.items():
            if 'test_' in key or 'pytest' in key or '.py' in key:
                continue
            marks.append(key)
        return marks

    def __write_points(self, points: list[Point]) -> None:
        """
        Writes the given points to InfluxDB.

        Args:
            points (list[Point]): The points to write to InfluxDB.
        """
        try:
            write_api = self.client.write_api(write_options=SYNCHRONOUS)
            write_api.write(bucket=self.bucket, record=points)
            write_api.close()
        except Exception as e:
            self.error = f'InfluxDB write error: {self.uri} - {e}'
            log.error(self.error)
