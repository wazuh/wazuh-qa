import {
  settingsAboutLink,
  settingsApiConfigurationLink,
  settingsConfigurationLink,
  settingsLogsLink,
  settingsMiscellaneousLink,
  settingsModulesLink,
  settingsSampleDataLink
} from '../../pageobjects/wazuh-menu/wazuh-menu.page';

export const SETTINGS_MENU_LINKS = {
  'API configuration': settingsApiConfigurationLink,
  Modules: settingsModulesLink,
  'Sample data': settingsSampleDataLink,
  Configuration: settingsConfigurationLink,
  Logs: settingsLogsLink,
  Miscellaneous: settingsMiscellaneousLink,
  About: settingsAboutLink
};
