---
name: 'Test: Wazuh App'
about: Test suite for the Wazuh App.
title: ''
labels: ''
assignees: ''

---

# Wazuh App test

| Version | Revision | Branch |
| --- | --- | --- |
| x.y.z | rev | branch |


## Installation

### Ubuntu

- [ ]  Clean install.

- [ ]  Clean install with X-Pack.

- [ ]  Upgrade install.

- [ ]  Upgrade install with X-pack.

### CentOS

- [ ]  Clean install.

- [ ]  Clean install with X-Pack.

- [ ]  Upgrade install.

- [ ]  Upgrade install with X-pack.

## Pattern Initialization

### Start Kibana, go to Management -> Index Pattern

- [ ]  Should have wazuh-alerts-3.x and wazuh-monitoring-3.x

- [ ]  None of the index-patterns should be default

## API management

### Click on the Wazuh button on the left bar on the Kibana interface

- [ ]  Should take you to Settings and warn you there's no API credentials available

- [ ]  The Current API text on the navbar should indicate that there's no API selected

- [ ]  The Current index pattern on the navbar should appear from the beginning.

### Filling Add API form badly once per every form field

- [ ]  Should appear the appropiate error message for every wrong inserted form field

### Filling "Add API" form correctly

- [ ]  Should connect successfully and show the data in the upper right corner

### Check manager button right after inserting API credentials

- [ ]  Should success and not modify anything on the fields

### Check the currently active extensions

- [ ]  Should be the same as the config.yml file

### Insert a new API and check every one with the Check button

- [ ]  Should not change the currently selected API

### Edit an API entry

- [ ]  The API is edited properly

### Go to a new tab (Manager)

- [ ]  After the healthcheck, should open the selected tab

### (Alternative) Press F5 after inserting the APIs

- [ ]  Should reload properly the currently active tab (Settings)

## Basic data flow test

### Check the initial number of checks of the healthcheck when opening the app

- [ ]  Should be 4 (the default config on the wazuh.yml file)

### Click in Modules/Agents tab and select a proper time range

- [ ]  Should appear a loading bar and disappear after finishing loading

### Go back to Panels subtab and activate a filter

- [ ]  The filter should be working

### Press F5 to reload the page

- [ ]  The filters should keep applied

### Go again to any Events subtab

- [ ]  Should appear selected the wazuh-alerts index pattern only

### Go back to Dashboard

- [ ]  The filter should be applied as a chip and also the visualizations show the correct data

### Click several times the app tabs when using the same tab

- [ ]  Filters should persist and not dissappear

### Search something on the searchbar, press Enter, remove the content and press Enter again

- [ ]  The visualizations watchers should not loose data

### Add a pinned filter and navigate to a different tab

- [ ]  The pinned filter should always be persistent

### Go to Settings and select different extensions, and then go back to Modules/Agents

### Go to Settings, select a different API with different extensions and go back to /Agents

- [ ]  The extensions configuration should keep on main Security events dashboard

### From Security Events, go to Events, and then go to Integrity Monitoring

- [ ]  Should not have loaded visualizations from General

## Pattern Selection

### Go to the Pattern tab in Settings

- [ ]  Should not appear an incompatible index-pattern

### Create a new index-pattern -> Go to Settings -> Select the new one

- [ ]  Should change successfully

### Go to Agents section

- [ ]  Visualizations should still show data

### Go to Events subtab

- [ ]  The index-pattern that you selected should be present on Discover

### Change to the previous pattern

- [ ]  Should change without errors

### Go back to Events subtab

- [ ]  The newly created index-pattern should be the selected one

## Management section

### Status

- [ ]  The current Wazuh Manager version should be the same version as the installed with the current selected API

### Ruleset

- [ ]  The Rules scrolling table should work properly

- [ ]  The visualizations should show 24h, and not be affected by the timestamp setting from the Modules/Agent tab

- [ ]  The search should work correctly applying different filters.

- [ ]  The Decoders scrolling table should work properly

### Groups

- [ ]  Searching agents, click agents and files should work correctly

- [ ]  All the scrolling tables from the tab (agents, files, groups) should work properly

### Logs

- [ ]The Logs scrolling table should work properly
- [ ]The search should work correctly
- [ ]  The "Play realtime" button should work properly and update the table every few seconds

## Agents

### Go to Agents Preview

- [ ]  The scrolling tab should work properly

### Go to a single agent

 The scrolling search bar from the upper right corner should work properly

### Change to a different agent or manager with the autocomplete component

- [ ]  The filters should update properly to the new location

## Miscellaneous checks

### Insert a secured API in Settings and check it

- [ ]  Should connect successfully, and not fail the form when inserting it

### Delete some files from a group configuration

- [ ]  The Content table of a group should show correctly the remaining files for each of the available groups

### Modify the config.yml checks. Uncomment the default ones and change the values

- [ ]  After restarting the Kibana service, should apply the new checks configuration and you shouldn't be able to see the pattern selector

### Modify the IP selector on config.yml (using false or 0)

- [ ]  After restarting the Kibana service, should apply the new configuration

### Cat the logs file (/usr/share/kibana/plugins/wazuh-logs/wazuhapp.log)

- [ ]  The file should be registering the logs, for example after restarting Kibana

## Breaking app checks

### Delete the index-patterns and restart the Kibana server

- [ ] Should re-create the default index-patterns and recover properly
- [ ] The number of known fields should be <tofix>.

### Delete the default wazuh-alerts index-pattern and create a new one (with a different ID), and restart Kibana

- [ ] The app should reload properly the new pattern and update its visualizations

### Delete the .kibana index with a CURL command and restart Kibana

- [ ] Should have again the default two index patterns

### Delete the .wazuh index with a CURL command and restart Kibana

- [ ] Should warn you again to insert the API credentials

### Delete the .wazuh-version index with a CURL command and restart Kibana

- [ ] Nothing weird should happen, and the version card on Settings -> About should show information

### Create a new index-pattern on the Management tab

- Assign that index-pattern to the app
- Delete the index-pattern
- Restart the Kibana server

- [ ] The app should recover properly after restarting

### Select the wazuh-alerts* index pattern on the app, create a wa* index pattern and select it on the app, and finally go again to Management -> Index patterns

- [ ] The new pattern should have the same number of known fields (182) without having to reboot Kibana