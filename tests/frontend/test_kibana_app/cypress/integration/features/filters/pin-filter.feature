Feature: Pin filter
   
    As Wazuh user 
    I want to pin a filter 
    in order to aplly it across the modules
  
   Scenario: The user add a new filer
    Given The kibana admin user is logged in using xpack and the wazuh logo is displayed
    When The user goes to security-event mod
    And The user adds a new filter
    Then The user check filter label is added
    And The user pins a filter
    And The user checks if the filter is displayed
    