Feature: Read Kibana logs
  As a kibana user
  I want to check the logs
  in order to see information about the system

  Scenario: Check Kibana logs
    Given The kibana admin user is logged in using basic authentication
    When The user navigates to Logs settings
    Then The Logs are displayed

  Scenario: Reload Kibana logs
    Given The kibana admin user is logged in using basic authentication
    When The user navigates to Logs settings
    And The user reloads the logs
    Then The Logs are displayed
    And The backend response indicates that the logs are reloaded