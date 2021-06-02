import { When } from 'cypress-cucumber-preprocessor/steps';
import { clickElement, getObject } from '../../../utils/driver';
import {
  managementButton,
  wazuhMenuButton,
  rulesButton,
} from '../../../pageobjects/wazuh-menu/wazuh-menu.page';

When('The user navigates to rules', () => {
  clickElement(wazuhMenuButton);
  clickElement(managementButton);
  clickElement(rulesButton);
  cy.wait(3000);
});
