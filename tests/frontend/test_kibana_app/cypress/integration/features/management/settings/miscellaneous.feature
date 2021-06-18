Feature: Run health checks
  As a kibana user
  I want to run the health check
  in order to validate everything is connected

  Scenario: Run health check
    Given The kibana admin user is logged in using basic authentication
    When The user navigates to Miscellaneous settings
    And The user runs the health checks
    Then The health checks are displayed without errors