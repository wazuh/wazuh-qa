Feature: disable modules

  As a kibana user
  I want to disable different modules
  in order to see them in the modules directory

  @DisableModules
  Scenario Outline: Disable modules, <Module Name>
    Given The kibana admin user is logged in using xpack and the wazuh logo is displayed
    When The user navigates to Modules settings
    And All modules are activates
    And The user deactivates the modules with <Module Name>
    Then The deactivated modules with <Module Name> are not displayed on home page
    Examples:
      | Module Name           |
      | Amazon AWS            |
      | Google Cloud Platform |
      | GitHub                |
      | OpenSCAP              |
      | CIS-CAT               |
      | VirusTotal            |
      | Osquery               |
      | Docker listener       |
      | GDPR                  |
      | HIPAA                 |
      | TSC                   |
