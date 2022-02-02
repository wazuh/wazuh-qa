Feature: enable and disable modules

  As a kibana user
  I want to enable and disable different modules
  in order to see them in the modules directory
  
  Background:
  Given The kibana admin user is logged in using xpack authentication
  @modules
  Scenario Outline: Enable and Disable modules, <Module Name>
    When The user navigates to Modules settings
    And The user activates the modules with <Module Name>
    Then The activated modules with <Module Name> are displayed on home page
    Examples:
      | Module Name           |
      | Amazon AWS            |
      | Google Cloud Platform |
      | GitHub                |
      | OpenSCAP              |
      | CIS-CAT               |
      | VirusTotal            |
      # | Osquery               |
      # | Docker listener       |
      # | GDPR                  |
      # | HIPAA                 |
      # | TSC                   |

    @modules
    Scenario Outline: Disable modules, <Module Name>
      # Given The kibana admin user is logged in using xpack authentication
      When The user navigates to Modules settings
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
        # | Osquery               |
        # | Docker listener       |
        # | GDPR                  |
        # | HIPAA                 |
        # | TSC                   |
