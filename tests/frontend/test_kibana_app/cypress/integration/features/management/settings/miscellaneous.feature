Feature: Run health checks

  As a kibana user
  I want to run the health check
  in order to validate everything is connected

  @miscellaneous
  Scenario: Run health check
    Given The kibana admin user is logged in using xpack and the wazuh logo is displayed
    When The user navigates to Miscellaneous settings
    And The user runs the health checks
    Then The application navigates to the health checks page
