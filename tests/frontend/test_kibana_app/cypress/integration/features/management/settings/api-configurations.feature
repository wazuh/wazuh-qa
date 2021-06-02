Feature: add, delete api configurations and switch between them

  As a kibana user
  i want to change API configuration settings
  in order to point different APIs

  Scenario: Check API configuration connection
    Given The kibana admin user is logged in using xpack authentication
    When The user navigates to API configuration settings
    And The user checks API configuration connection
    Then The connection success toast is displayed