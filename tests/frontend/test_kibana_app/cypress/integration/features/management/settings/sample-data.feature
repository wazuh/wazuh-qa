Feature: add sample data to modules

  As a kibana user
  i want to add sample data to modules
  in order to populate graphics

  Scenario: Add sample security information data
    Given The kibana admin user is logged in using odfe authentication
    When The user navigates to Sample data settings
    And The user adds sample security information data
    Then The confirmation toast is displayed

  Scenario: Add sample auditing and policy monitoring data
    Given The kibana admin user is logged in using odfe authentication
    When The user navigates to Sample data settings
    And The user adds sample auditing and policy monitoring data
    Then The confirmation toast is displayed

  Scenario: Add sample threat detection and response data
    Given The kibana admin user is logged in using odfe authentication
    When The user navigates to Sample data settings
    And The user adds sample threat detection and response data
    Then The confirmation toast is displayed

    Scenario: Delete all sample data
      Given The kibana admin user is logged in using odfe authentication
      When The user navigates to Sample data settings
      And The user removes sample security information data
      And The user removes sample auditing and policy monitoring data
      And The user removes sample threat detection and response data
      Then The confirmation toast is displayed
