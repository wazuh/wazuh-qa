import { clickElement, elementIsVisible } from '../../../utils/driver';
import { MODULES_CARDS, MODULES_SETTINGS } from '../../../utils/mappers/modules-mapper';
import {
  modulesButton,
  modulesDirectoryLink,
  wazuhMenuButton
} from '../../../pageobjects/wazuh-menu/wazuh-menu.page';

Then('The activated modules with {} are displayed on home page', (moduleName) => {
  elementIsVisible(wazuhMenuButton);
  clickElement(wazuhMenuButton);
  cy.wait(2000)
  elementIsVisible(modulesButton);
  clickElement(modulesButton);
  cy.wait(2000)
  elementIsVisible(modulesDirectoryLink);
  clickElement(modulesDirectoryLink);
  cy.wait(2000)
  elementIsVisible(MODULES_CARDS[moduleName]);
});
