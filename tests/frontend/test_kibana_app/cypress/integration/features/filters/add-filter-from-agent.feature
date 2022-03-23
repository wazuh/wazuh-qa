Feature: Validate that the pinned filter label is displayed 
   
    As Wazuh user 
    i want to set a new filter from the agent page 
    in order to manage them
  
   Scenario Outline: The user add and pin filter - Check across the modules
    Given The kibana admin user is logged in using xpack and the wazuh logo is displayed
    When The user nav to the agent page
    And The user navigates to the agent dashboard
    And The user navigates to <Module Name>
    And The user add a new filter
    And The user pin a filter
    And The user navigates to the agent page
    And The user navigates to the agent dashboard
    And The user navigates to <Module Name>
    Then The user check if the filter is displayed
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