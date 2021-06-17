import { When } from 'cypress-cucumber-preprocessor/steps';
import { clickElement } from '../../utils/driver';
import { settingsButton, wazuhMenuButton } from '../../pageobjects/wazuh-menu/wazuh-menu.page';
import { SETTINGS_MENU_LINKS } from '../../utils/mappers/settings-mapper';

When('The user navigates to {} settings', (menuOption) => {
  clickElement(wazuhMenuButton);
  clickElement(settingsButton);
  clickElement(SETTINGS_MENU_LINKS[menuOption]);
});
