class TestResult:
    """ The class holds the reports resulting from the execution of one battery of tests.

    Attributes:
        html_report_dir_path (str, None): Local file path pointing to the html report
        plain_report_file_path (str, None):  Local file path pointing to the plain report
        custom_report_file_path (str, None):  Local file path pointing to the custom report

    Args:
        html_report_dir_path (str, None): Local file path pointing to the html report
        plain_report_file_path (str, None):  Local file path pointing to the plain report
        custom_report_file_path (str, None):  Local file path pointing to the custom report
    """

    def __init__(self, html_report_file_path=None, plain_report_file_path=None, custom_report_file_path=None,
                 test_name=None):
        self.html_report_file_path = html_report_file_path
        self.plain_report_file_path = plain_report_file_path
        self.custom_report_file_path = custom_report_file_path
        self.test_name = test_name

    def __str__(self):
        result = '\n' * 2

        with open(self.plain_report_file_path) as plain_report_file:
            result += plain_report_file.read()

        result += '\n' * 2

        return result

    def generate_custom_report(self):
        pass
