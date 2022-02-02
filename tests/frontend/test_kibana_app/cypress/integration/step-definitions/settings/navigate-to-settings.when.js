import { When } from 'cypress-cucumber-preprocessor/steps';
import { clickElement , elementIsVisible} from '../../utils/driver';
import { settingsButton, wazuhMenuButton } from '../../pageobjects/wazuh-menu/wazuh-menu.page';
import { SETTINGS_MENU_LINKS } from '../../utils/mappers/settings-mapper';

When('The user navigates to {} settings', (menuOption) => {
  clickElement(wazuhMenuButton);
  elementIsVisible(settingsButton);
  clickElement(settingsButton);
  cy.wait(2000)
  elementIsVisible(SETTINGS_MENU_LINKS[menuOption]);
  clickElement(SETTINGS_MENU_LINKS[menuOption]);
  cy.wait(2000)
});
