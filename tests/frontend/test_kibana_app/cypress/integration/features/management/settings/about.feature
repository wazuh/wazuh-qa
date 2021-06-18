Feature: Wazuh version information

  As a kibana user
  I want to check the about information
  in order to see information about the system

  Scenario: Check Wazuh version information
    Given The kibana admin user is logged in using basic authentication
    When The user navigates to About settings
    Then The Wazuh information is displayed