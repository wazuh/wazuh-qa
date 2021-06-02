import {
  settingsApiConfigurationButton,
  settingsModulesButton,
  settingsSampleDataButton,
  settingsConfigurationButton,
  settingsLogsButton,
  settingsAboutButton
} from '../pageobjects/wazuh-menu/wazuh-menu.page';

export const SETTINGS_MENU_LINKS = {
  'API configuration': settingsApiConfigurationButton,
  Modules: settingsModulesButton,
  'Sample data': settingsSampleDataButton,
  Configuration: settingsConfigurationButton,
  Logs: settingsLogsButton,
  about: settingsAboutButton
};
