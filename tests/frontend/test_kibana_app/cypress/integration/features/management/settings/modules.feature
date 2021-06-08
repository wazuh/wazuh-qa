Feature: enable and disable modules

  As a kibana user
  I want to enable and disable different modules
  in order to see them in the modules directory

  Scenario: enable all modules
    Given The kibana admin user is logged in using odfe authentication
    And The user wants to activate the following modules
      |Module Name            |
      |Amazon AWS             |
      |Google Cloud Platform  |
      |OpenSCAP               |
      |CIS-CAT                |
      |VirusTotal             |
      |Osquery                |
      |Docker listener        |
      |GDPR                   |
      |HIPAA                  |
      |TSC                    |
    When The user navigates to Modules settings
    And The user activates the modules
    Then The activated modules are displayed on home page
