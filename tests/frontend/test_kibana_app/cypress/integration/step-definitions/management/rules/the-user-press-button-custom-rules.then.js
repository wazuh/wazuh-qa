import { Then } from 'cypress-cucumber-preprocessor/steps';
import { getObject } from '../../../utils/driver';
import { customRulesButtonSelector } from '../../../pageobjects/wazuh-menu/rules.page';

Then('The user press button custom rules', () => {
  cy.wait(3000);
  getObject(customRulesButtonSelector)
    .click();
  cy.wait(3000);
});
