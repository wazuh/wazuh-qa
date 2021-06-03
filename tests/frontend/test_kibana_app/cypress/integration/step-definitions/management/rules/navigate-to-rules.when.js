import { When } from 'cypress-cucumber-preprocessor/steps';
import { clickElement, getElement, validateURLIncludes } from '../../../utils/driver';
import {
  managementButton,
  wazuhMenuButton,
  rulesLink,
} from '../../../pageobjects/wazuh-menu/wazuh-menu.page';

When('The user navigates to rules', () => {
  clickElement(wazuhMenuButton);
  clickElement(managementButton);
<<<<<<< HEAD
  clickElement(rulesButton);
  validateURLIncludes('/manager/?tab=rules');
=======
  clickElement(rulesLink);
  cy.wait(3000);
>>>>>>> Update selectors
});
