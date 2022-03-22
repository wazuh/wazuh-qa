import { When } from 'cypress-cucumber-preprocessor/steps';
import { navigate, clickElement , elementIsVisible} from '../../utils/driver';
import { settingsButton, wazuhMenuButton } from '../../pageobjects/wazuh-menu/wazuh-menu.page';
import { SETTINGS_MENU_LINKS } from '../../utils/mappers/settings-mapper';

When('The user navigates to {} settings', (menuOption) => {
  elementIsVisible(wazuhMenuButton);
  clickElement(wazuhMenuButton);
  elementIsVisible(settingsButton);
  clickElement(settingsButton);
  elementIsVisible(SETTINGS_MENU_LINKS[menuOption]);
  clickElement(SETTINGS_MENU_LINKS[menuOption]);
});
