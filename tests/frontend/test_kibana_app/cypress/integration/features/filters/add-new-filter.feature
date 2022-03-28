Feature: Validate that the added filter label is displayed 
   
    As Wazuh user 
    I want to set a new filter 
    in order to manage them
  
   Scenario: The user add a new filer
    Given The kibana admin user is logged in using xpack and the wazuh logo is displayed
    When The user goes to security-event mod
    And The user adds a new filter
    Then The user checks filter label is added
    