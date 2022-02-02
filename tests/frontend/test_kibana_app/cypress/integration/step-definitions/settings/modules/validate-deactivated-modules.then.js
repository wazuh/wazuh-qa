import { clickElement, elementIsNotVisible, elementIsVisible } from '../../../utils/driver';
import {
  modulesButton,
  modulesDirectoryLink,
  wazuhMenuButton,
} from '../../../pageobjects/wazuh-menu/wazuh-menu.page';
import { MODULES_CARDS } from '../../../utils/mappers/modules-mapper';

Then('The deactivated modules with {} are not displayed on home page', (moduleName) => {
  elementIsVisible(wazuhMenuButton);
  clickElement(wazuhMenuButton);
  cy.wait(2000)
  elementIsVisible(modulesButton);
  clickElement(modulesButton);
  cy.wait(2000)
  elementIsVisible(modulesDirectoryLink);
  clickElement(modulesDirectoryLink);
  cy.wait(2000)
  elementIsNotVisible(MODULES_CARDS[moduleName]);
});
