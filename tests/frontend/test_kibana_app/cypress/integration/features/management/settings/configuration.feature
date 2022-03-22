Feature: add Configuration to modules

    As a Kibana user
    I want to add sample data indices
    in order to check modules

    @Configuration
    Scenario: Add sample data
        Given The kibana admin user is logged in using xpack and the wazuh logo is displayed
        When The user navigates to Configuration settings
        Then The app current settings are displayed