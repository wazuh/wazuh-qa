Feature: Should List Decoders And Show The Pager

  As a kibana user
  i want to see the Decoders pages
  in order to manage them

  Scenario: Should List Decoders And Show The Pager
    Given The kibana admin user is logged in using xpack and the wazuh logo is displayed
    When The user navigates to decoders
    Then The user should see the decoders

  Scenario: Should List Custom Decoders And Show The Pager
    Given The kibana admin user is logged in using xpack and the wazuh logo is displayed
    When The user navigates to decoders
    When The user press button custom decoders
    Then The user should see the decoders

  Scenario: Should can edit a decoder
    Given The kibana admin user is logged in using xpack and the wazuh logo is displayed
    When The user navigates to decoders
    When The user press button custom decoders
    When The user presses the edit decoder button and edits it
    Then The user should see the message
