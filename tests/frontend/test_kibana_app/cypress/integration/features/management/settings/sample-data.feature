Feature: add sample data to modules

  As a Kibana user
  I want to add sample data indices
  in order to check modules

  Scenario: Add sample data
    Given The kibana admin user is logged in using odfe authentication
    When The user navigates to Sample data settings
    And The user adds sample data for
      | security information            |
      | auditing and policy monitoring  |
      | threat detection and response   |
    Then The add data success toasts are displayed

    Scenario: Delete all sample data
      Given The kibana admin user is logged in using odfe authentication
      When The user navigates to Sample data settings
      And The user removes sample data for
      | security information            |
      | auditing and policy monitoring  |
      | threat detection and response   |
    Then The remove data success toasts are displayed
