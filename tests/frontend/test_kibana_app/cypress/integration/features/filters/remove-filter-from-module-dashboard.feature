Feature: Validate that the added filter label is remove after click remove filter option
   
    As Wazuh user 
    I want to set a new filter 
    in order to manage them
  
   Scenario Outline: The user remove an added filter - Module - Dashboard
    Given The kibana admin user is logged in using xpack and the wazuh logo is displayed
    When The user goes to <Module Name>
    And The user adds a new filter
    And The user checks filter label is added
    And The user removes the applied filter
    Then The user checks filter label is not added
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