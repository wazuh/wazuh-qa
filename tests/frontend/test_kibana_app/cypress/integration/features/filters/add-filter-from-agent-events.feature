Feature: Validate that the pinned filter label is displayed 
   
    As Wazuh user 
    I want to set a new filter from the agent page 
    in order to manage them
  
   Scenario Outline: The user add and pin filter - Check across the modules - from event page
    Given The kibana admin user is logged in using xpack and the wazuh logo is displayed
    When The user navigates to the agent page
    And The user navigates to the agent dashboard
    And The user navigates to agentModule <Module Name>
    And The user moves to events page
    And The user adds a new filter
    And The user pins a filter
    And The user navigates to the agent page
    And The user navigates to the agent dashboard
    And The user navigates to agentModule <Module Name>
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
      