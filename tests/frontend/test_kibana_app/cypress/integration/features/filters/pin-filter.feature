Feature: Pin filter
   
    As Wazuh user 
    i want to pin a filter 
    in order to aplly it across the modules
  
   Scenario: The user add a new filer
    Given The kibana admin user is logged in using xpack and the wazuh logo is displayed
    When The user navigates to security-events module
    And The user add a new filter
    Then The user check filter label is added
    And The user pin a filter
    And The user check if the filter is apply across the modules
    