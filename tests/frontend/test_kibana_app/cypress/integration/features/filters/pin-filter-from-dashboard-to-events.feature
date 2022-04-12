Feature: Pin filter
   
    As Wazuh user 
    I want to pin a filter 
    in order to aplly it across the modules
  
   Scenario Outline: The user add and pin new filer - across the modules - from dashboard to event page
    Given The kibana admin user is logged in using xpack and the wazuh logo is displayed
    When The user goes to <Module Name>
    And The user adds a new filter
    And The user checks filter label is added
    And The user pins a filter
    And The user checks if the filter is displayed
    And The user navigates overview page
    And The user goes to <Module Name>
    And The user moves to events page
    Then The user checks if the filter is displayed
    Examples:
      | Module Name           |
      | Security Events       |
      | Integrity Monitoring  |
      | System Auditing       |
      | Vulnerabilities       |
      | Mitre & Attack        |
      | GDPR                  |
      | HIPAA                 |
      | NIST                  |
      | TSC                   |
      | Policy Monitoring     |
      | PCIDSS                |
      